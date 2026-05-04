package ch.admin.bj.swiyu.swiyu_test_wallet.flows;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.issuer_metadata.IssuerMetadataAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@ActiveProfiles({"issuer-complete"})
public class SignedRenewalFlowTest extends BaseTest {

    @BeforeAll
    void setUp() {
        wallet.setUseDPoP(true);
        wallet.setUseEncryption(true);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-763",
            summary = "Renewal flow with signed metadata with a tenant ID",
            description = """
                    This test validates the credential renewal flow when the issuer uses signed metadata that includes a tenant ID. 
                    It ensures that the wallet can correctly process issuer metadata containing a tenant identifier and successfully obtain credentials.
                    
                    The test also verifies that the renewal operation works as expected in this context, resulting in a new batch of valid credentials while preserving the integrity, uniqueness, and expected subject disclosures of the issued credentials.
                    """)
    @Tag(ReportingTags.UCI_I1E)
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This fix is not available yet"
    )
    void givenIssuerWithSignedMetadataAndTenantId_thenCredentialsAreRenewed_whenWalletPerformsRenewalFlow() {
        // Given
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId, subjectClaims);
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        // Then
        IssuerMetadataAssert.assertThat(batchEntry.getIssuerMetadata()).hasTenantId();
        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);

        // Given
        batchEntry.clearIssuedCredentials();

        // When
        final var credentialResponse = wallet.renewedCredentials(batchEntry);
        assertThat(credentialResponse).isNotNull();

        // Then
        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);

        // When
        for (int index = 0; index < batchEntry.getIssuedCredentials().size(); index++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(true)
                    .encrypted()
                    .createManagementResponse();
            final RequestObject verificationDetails = wallet
                    .getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
            verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
            final String presentation = batchEntry.createPresentationForSdJwtIndex(index, verificationDetails);
            wallet.respondToVerification(verificationDetails, presentation);
            // Then
            verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
        }
    }
}

