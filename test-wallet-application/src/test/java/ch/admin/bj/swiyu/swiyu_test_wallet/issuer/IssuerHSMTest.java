package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@ActiveProfiles({"issuer-hsm"})
public class IssuerHSMTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-745",
            summary = "Todo",
            description = """
                    Todo
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    void updateStatusList_whenKeyMaterialOverrideConfiguration_thenSuccess() {
        // Given
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId,
                subjectClaims);
        final WalletBatchEntry entry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        // Then
        SdJwtBatchAssert.assertThat(entry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);

        // When
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(true)
                .createManagementResponse();
        final RequestObject verificationDetails = wallet
                .getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
        final String presentation = entry.createPresentationForSdJwtIndex(0, verificationDetails);
        wallet.respondToVerification(SwiyuApiVersionConfig.V1, verificationDetails, presentation);
        // Then
        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
    }

}
