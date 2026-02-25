package ch.admin.bj.swiyu.swiyu_test_wallet.flows;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@ActiveProfiles({"issuer-strict"})
public class UnlinkabilityTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-506",
            summary = "Unlinkability validation across issuance and renewals",
            description = """
                    This test validates the unlinkability property of the Batch Credential Issuance mechanism.
                    
                    A single credential offer results in the issuance of multiple credentials sharing
                    the same credential subject claims and format. While the subject claims remains identical,
                    each issued credential must contain distinct cryptographic material in order to
                    prevent correlation between different presentations.

                    In addition to batch issuance, the test also validates unlinkability during
                    credential renewal flows. When a credential is renewed, even if the subject
                    claims remain unchanged, the newly issued credential
                    must not be cryptographically linkable to the previous one.

                    The test verifies that:
                    - All credentials share the same credential subject claims,
                    - Each credential contains a unique issuer signature,
                    - Each credential is bound to a unique holder binding key (cnf.jwk),
                    - Status list indexes are unique and non-sequential,
                    - No constant or reusable cryptographic identifiers (such as a static cnf.kid)
                    introduce correlation signals.
                    
                    This simulation ensures that issuer behavior prevent
                    correlation across batch issuance and renewals.
                    """
    )
    @Tag(ReportingTags.UCI_S1)
    @Tag(ReportingTags.UCI_C1)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.HAPPY_PATH)
    public void shouldEnsureUnlinkabilityAcrossBatchIssuanceAndRenewals() {
        wallet.setUseEncryption(true);
        wallet.setUseDPoP(true);

        final int renewalCount = 5;

        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final CredentialWithDeeplinkResponse response =
                issuerManager.createCredentialWithSignedJwt(jwtKey, keyId,
                        CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);

        final List<WalletBatchEntry> batchEntries = new ArrayList<>();
        final WalletBatchEntry batchEntry = wallet.collectOfferV1(toUri(response.getOfferDeeplink()));
        batchEntries.add(batchEntry);

        for (int i = 0; i < renewalCount; i++) {
            WalletBatchEntry renewedBatchEntry = batchEntry.duplicate();
            wallet.renewedCredentials(renewedBatchEntry);
            batchEntries.add(renewedBatchEntry);
        }

        final List<String> vcs = batchEntries.stream()
                .map(WalletBatchEntry::getIssuedCredentials)
                .flatMap(List::stream)
                .toList();

        SdJwtBatchAssert.assertThat(vcs)
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE * (renewalCount + 1))
                .areUnique()
                .haveUniqueIssuerSignatures()
                .haveUniqueHolderBindingKeys()
                .haveUniqueStatusListIndexes()
                .haveNonSequentialStatusListIndexes()
                .haveNonConstantCnfKid()
                .haveUniqueCnfPublicKeys()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);
    }
}
