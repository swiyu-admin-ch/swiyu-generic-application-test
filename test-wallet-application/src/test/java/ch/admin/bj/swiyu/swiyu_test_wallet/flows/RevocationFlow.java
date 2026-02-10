package ch.admin.bj.swiyu.swiyu_test_wallet.flows;

import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.util.Map;
import java.util.concurrent.TimeUnit;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
public class RevocationFlow extends BaseTest {

    @BeforeEach
    void setupRevocationTest() {
        MockServerClientConfig.resetRevokedStatusList();
    }

    @Test
    void unboundNonDeferredCredential_whenIssuedSingleAndVerifiedWithDif_thenSuccess() throws InterruptedException {
        // Given
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId,
                subjectClaims);
        final WalletEntry entry = wallet.collectOffer(SwiyuApiVersionConfig.ID2, toUri(offer.getOfferDeeplink()));
        // Then
        SdJwtAssert.assertThat(entry.getVerifiableCredential())
                .hasExactlyInAnyOrderDisclosures(subjectClaims);

        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.REVOKED);
        Thread.sleep(TimeUnit.SECONDS.toMillis(3));

        MockServerClientConfig.setRevokedStatusList(true);

        // When
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .createManagementResponse();
        final RequestObject verificationDetails = wallet
                .getVerificationDetailsUnsigned(toUri(verification.getVerificationDeeplink()));
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
        wallet.respondToVerification(SwiyuApiVersionConfig.ID2, verificationDetails, entry.getVerifiableCredential());
        // Then
        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
    }

    @AfterEach
    void cleanup() {
        MockServerClientConfig.resetRevokedStatusList();
    }
}
