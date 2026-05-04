package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierStatusListCacheRegressionTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Verifier fails status-list resolution after Spring Boot 4 migration",
            description = """
                    This test validates that the Verifier OID4VP flow currently rejects a credential carrying a
                    token status list because the status-list resolver cache condition cannot resolve the
                    cacheProperties bean after the Spring Boot 4 migration.
                    """
    )
    @Tag(ReportingTags.UCV_O2)
    @Disabled
    void credentialWinithStatusList_whenPresentedToVerifier_thenFailsBecauseCachePropertiesBeanIsMissing() {

        // Given
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT,
                CredentialSubjectFixtures.completeEmployeeProfile()
        );
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final String verifiableCredential = batchEntry.getVerifiableCredential(0);

        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(false)
                .createManagementResponse();
        final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(verification.getVerificationDeeplink());

        // When
        final HttpClientErrorException.BadRequest ex = assertThrows(
                HttpClientErrorException.BadRequest.class,
                () -> wallet.respondToVerification(verificationDetails, verifiableCredential)
        );

        // Then
        assertThat(ex.getResponseBodyAsString())
                .contains("unresolvable_status_list")
                .contains("Could not retrieve status list vc");

        assertThat(verifierContainer.getLogs())
                .contains("Could not retrieve status list vc.")
                .contains("SpelEvaluationException")
                .contains("No bean named 'cacheProperties' available");
    }
}
