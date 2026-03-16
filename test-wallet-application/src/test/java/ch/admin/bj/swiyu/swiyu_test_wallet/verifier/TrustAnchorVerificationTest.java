package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class TrustAnchorVerificationTest extends BaseTest {

    @Autowired
    private MockServerClientConfig mockServerClientConfig;
    @Autowired
    private IssuerImageConfig issuerImageConfig;

    @Test
    @XrayTest(
            key = "EIDOMNI-195",
            summary = "Successful verification through a valid Trust Anchor",
            description = """
                    This test validates that a verifier successfully accepts a credential issued by a trusted issuer
                    when verified through a configured Trust Anchor. The verification succeeds for both SWIYU API versions
                    (OID4VP standard and DCQL-based), ensuring that trust relationships are properly validated.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1A)
    @Tag(ReportingTags.HAPPY_PATH)
    void verificationWithValidTrustAnchor_thenSuccess() {
        // Given
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(response.getOfferDeeplink()));
        assertThat(batchEntry.getCredentialOffer()).isNotNull();

        // When
        final TrustAnchor anchor = new TrustAnchor()
                .did(trustConfig.getTrustDid())
                .trustRegistryUri(String.format("http://%s/trusted", MockServerClientConfig.MOCKSERVER_HOST));
        final ManagementResponse verification = verifierManager.verificationRequest()
                .trustAnchor(anchor)
                .withDCQL()
                .createManagementResponse();

        final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
        final String presentation = batchEntry.createPresentationForSdJwtIndex(0, verificationDetails);
        wallet.respondToVerificationV1(verificationDetails, presentation);

        // Then
        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-397",
            summary = "Verification rejected when issuer not trusted via Trust Anchor",
            description = """
                    This test ensures that verification fails when the issuer is not trusted through the provided
                    Trust Anchor. The test validates that trust anchor validation prevents accepting credentials from
                    untrusted issuers across both SWIYU API versions.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1B)
    @Tag(ReportingTags.EDGE_CASE)
    void verificationWithUntrustedIssuer_thenFails() {
        // Given
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(response.getOfferDeeplink()));
        assertThat(batchEntry.getCredentialOffer()).isNotNull();

        // When
        final TrustAnchor anchor = new TrustAnchor()
                .did(trustConfig.getTrustDid())
                .trustRegistryUri(String.format("http://%s/untrusted", MockServerClientConfig.MOCKSERVER_HOST));
        final ManagementResponse verification = verifierManager.verificationRequest()
                .trustAnchor(anchor)
                .withDCQL()
                .createManagementResponse();

        final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
        final String presentation = batchEntry.createPresentationForSdJwtIndex(0, verificationDetails);

        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class,
                () -> wallet.respondToVerificationV1(verificationDetails, presentation));

        // Then
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasError("invalid_transaction_data")
                .hasDetail("issuer_not_accepted")
                .hasErrorDescription("Issuer not in list of accepted issuers or connected to trust anchor");

        verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
    }
}
