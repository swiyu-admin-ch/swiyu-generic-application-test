package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class BatchTest extends BaseTest {

    @BeforeEach
    void beforeEach() {
        wallet.setUseEncryption(false);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-388",
            summary = "Successful SD-JWT batch issuance flow",
            description = """
                    This test validates that the issuer successfully performs batch issuance of multiple SD-JWT credentials
                    in a single offer with encryption enabled. The batch credentials receive non-sequential status list indexes
                    to ensure proper randomization and uniqueness across the status list.
                    """
    )
    @Tag(ReportingTags.UCI_S1)
    @Tag(ReportingTags.UCI_C1)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void batchIssuanceFlow_thenSuccess() {
        issuerManager.createStatusList(10000, 2);

        wallet.setUseEncryption(true);

        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final CredentialWithDeeplinkResponse response =
                issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT, subjectClaims);

        final WalletBatchEntry batchEntry = wallet.collectOfferV1(toUri(response.getOfferDeeplink()));

        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
            .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
            .areUnique()
            .haveUniqueIssuerSignatures()
            .haveUniqueHolderBindingKeys()
            .haveUniqueStatusListIndexes()
            .haveNonSequentialStatusListIndexes()
            .haveNonConstantCnfKid()
            .haveUniqueCnfPublicKeys()
            .haveDayRoundedIat()
            .haveDayRoundedExpIfPresent()
            .allHaveExactlyInAnyOrderDisclosures(subjectClaims);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-395",
            summary = "Batch issuance rejected when status list capacity exceeded",
            description = """
                    This test ensures that the issuer correctly rejects batch SD-JWT issuance requests when the number of
                    credentials requested exceeds the remaining capacity of the configured status list, returning HTTP 400
                    with an appropriate error message.
                    """
    )
    @Tag(ReportingTags.UCI_S1)
    @Tag(ReportingTags.UCI_C1)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void batchIssuanceFlowExceedStatusList_thenReject() throws SQLException {
        final int statusListLength = 2;

        issuerManager.createStatusList(statusListLength, 2);

        wallet.setUseEncryption(true);

        HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
            issuerManager.createCredentialOffer("bound_example_sd_jwt");
        });

        assertThat(ex.getStatusCode().value())
                .as("Expected HTTP 400 Bad Request")
                .isEqualTo(400);

        assertThat(ex.getMessage())
                .as("Expected message to contain Bad Request and detail about max length exceeded")
                .contains("\"detail\":\"Too few status indexes remain in status list");
    }

    private boolean areSequential(final List<Integer> indexes) {
        if (indexes.size() < 2) return false;

        final List<Integer> sorted = indexes.stream().sorted().collect(Collectors.toList());
        for (int i = 1; i < sorted.size(); i++) {
            if (sorted.get(i) - sorted.get(i - 1) != 1) return false;
        }

        return true;
    }

    private List<Integer> getUsedIndexesFromDb() throws SQLException {
        final List<Integer> indexes = new ArrayList<>();

        final String query = """
                    SELECT index
                    FROM %s.credential_offer_status
                    ORDER BY index ASC
                """.formatted(issuerImageConfig.getDbSchema());

        try (ResultSet rs = stmt.executeQuery(query)) {
            while (rs.next()) {
                indexes.add(rs.getInt("index"));
            }
        }

        return indexes;
    }
}
