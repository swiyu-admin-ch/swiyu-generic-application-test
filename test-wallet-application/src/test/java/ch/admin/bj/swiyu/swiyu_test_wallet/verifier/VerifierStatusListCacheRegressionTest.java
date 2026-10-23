package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JwtSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.net.URI;
import java.util.List;

import static ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result.CredentialEvaluationAssert.assertEvaluation;
import static ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result.TokenStatusListValues.VALID;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.DEFAULT_CREDENTIAL_ID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockserver.model.HttpRequest.request;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierStatusListCacheRegressionTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-966",
            summary = "Verifier fails status-list resolution cache",
            description = """
                    This test validates that the Verifier OID4VP flow currently rejects a credential carrying a
                    token status list because the status-list resolver cache condition cannot resolve the
                    cacheProperties bean.
                    """
    )
    @Tag(ReportingTags.HAPPY_PATH)
    @Tag(ReportingTags.UCV_O2_SUBMIT_VERIFICATION_PRESENTATION)
    @Tag(ReportingTags.UCV_O2A_VERIFY_PRESENTATION_SUBMISSION_AND_SD_JWT_CREDENTIAL)
    @Tag(ReportingTags.UCV_O2C_CHECK_VC_STATUS_IN_REGISTRY)
    void credentialWithStatusList_whenPresentedToVerifier_thenStatusIsResolvedAndVerificationSucceeds() {

        // Given
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT,
                CredentialSubjectFixtures.completeEmployeeProfile()
        );
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final String verifiableCredential = batchEntry.getVerifiableCredential(0);
        final String statusListUri = JwtSupport.decodePayloadToJsonNode(verifiableCredential.split("~", 2)[0])
                .path("status").path("status_list").path("uri").asString();
        assertThat(statusListUri)
                .as("The issued credential must reference a status list")
                .isNotBlank();
        final var statusListRequest = request()
                .withMethod("GET")
                .withPath(URI.create(statusListUri).getPath());
        final int statusListRequestsBefore = mockServerClient.retrieveRecordedRequests(statusListRequest).length;

        wallet.setUseEncryption(true);
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(false)
                .encrypted()
                .createManagementResponse();
        final RequestObject verificationDetails = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());

        // When
        final var walletResponse = wallet.respondToVerificationWithVpTokens(
                verificationDetails, List.of(verifiableCredential));

        // Then
        assertThat(walletResponse.getStatusCode().value())
                .isEqualTo(200);
        final ManagementResponse result = verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
        assertEvaluation(result, DEFAULT_CREDENTIAL_ID, true, VALID);
        assertThat(mockServerClient.retrieveRecordedRequests(statusListRequest))
                .as("The Verifier must fetch the status list referenced by the presented credential")
                .hasSizeGreaterThan(statusListRequestsBefore);
    }
}
