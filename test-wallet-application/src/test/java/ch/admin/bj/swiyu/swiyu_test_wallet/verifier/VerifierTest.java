package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager.VerificationRequestBuilder;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierTest extends BaseTest {
    @Test
    @XrayTest(
            key = "EIDOMNI-463",
            summary = "Successful deeplink creation for verification request",
            description = """
                    This test validates that a Business Verifier can successfully create a verification request
                    and generate a verification deeplink through the verifier management API. The deeplink follows
                    the correct URI scheme and can be used by the wallet to initiate the verification flow.
                    """
    )
    @Tag(ReportingTags.UCV_M1)
    @Tag(ReportingTags.UCV_M1B)
    @Tag(ReportingTags.HAPPY_PATH)
    void verifierProvidesDeeplink() {
        final ManagementResponse deeplink = verifierManager.verificationRequest().acceptedIssuerDid(UUID.randomUUID().toString()).createManagementResponse();
        assertThat(deeplink.getVerificationDeeplink())
                .isNotNull()
                .startsWith("swiyu-verify://");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-557",
            summary = "Verification request creation is rejected when presentation definition is missing",
            description = """
                    This test validates that the Business Verifier management API correctly rejects
                    verification request creation when the required presentation definition is not provided.
                    The validation ensures that complete and valid presentation definitions are mandatory
                    for all verification requests.
                    """
    )
    @Tag(ReportingTags.UCV_M1)
    @Tag(ReportingTags.EDGE_CASE)
    void managementCreateVerification_missingPresentationDefinition_thenRejected() {
        final VerificationRequestBuilder verificationRequest = verifierManager.verificationRequest()
                .acceptedIssuerDid(UUID.randomUUID().toString())
                .presentationDefinition(null);
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () ->
                verificationRequest.createManagementResponse()
        );

        assertThat(errorCode(ex)).isEqualTo(400);

        assertThat(errorJson(ex))
                .containsExactlyInAnyOrderEntriesOf(Map.of(
                        "error_description", "PresentationDefinition must be provided"
                ));
    }


    @Test
    @XrayTest(
            key = "EIDOMNI-562",
            summary = "Verification retrieval fails when verification ID does not exist",
            description = """
                    This test validates that the Business Verifier management API correctly rejects
                    attempts to retrieve verification details using a non-existent verification ID.
                    The API returns HTTP 404 with an appropriate error message indicating that the
                    requested verification was not found.
                    """
    )
    @Tag(ReportingTags.UCV_M3)
    @Tag(ReportingTags.EDGE_CASE)
    void managementGetVerification_randomId_thenRejected() {
        final UUID unknownId = UUID.randomUUID();

        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () ->
                verifierManager.getVerificationById(unknownId)
        );

        assertThat(errorCode(ex)).isEqualTo(404);
        assertThat(errorJson(ex))
                .containsExactlyInAnyOrderEntriesOf(Map.of(
                        "detail", String.format("The verification with the identifier '%s' was not found", unknownId.toString())
                ));
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-559",
            summary = "Verification presentation submission is rejected when presentation_submission field is missing",
            description = """
                    This test validates that the Verifier OID4VP endpoint correctly rejects presentation submissions
                    that are missing the required presentation_submission field. The wallet must include both vp_token
                    and presentation_submission in the response to be accepted.
                    """
    )
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.EDGE_CASE)
    void missingPresentationSubmission_thenRejected() {
        final CredentialWithDeeplinkResponse response =
                issuerManager.createCredentialOffer("bound_example_sd_jwt");

        final WalletBatchEntry batchEntry =
                wallet.collectOffer(toUri(response.getOfferDeeplink()));
        assertThat(batchEntry.getCredentialOffer()).isNotNull();

        final String deepLink = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversity()
                .create();

        final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(deepLink);
        final String res = batchEntry.createPresentationForSdJwtIndex(0, verificationDetails);

        // Spy wallet to simulate missing presentation_submission
        final Wallet spyWallet = Mockito.spy(wallet);
        Mockito.doAnswer(invocation -> {
            final RequestObject requestObject = invocation.getArgument(0);
            final String token = invocation.getArgument(1);

            final var formData = new LinkedMultiValueMap<String, String>();
            formData.add("vp_token", token);

            spyWallet.getRestClient().post()
                    .uri(spyWallet.getVerifierContext().getContextualizedUri(
                            ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri(requestObject.getResponseUri())
                    ))
                    .headers(headers -> {
                        headers.add(org.springframework.http.HttpHeaders.CONTENT_TYPE,
                                org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE);
                        headers.add("SWIYU-API-Version", SwiyuApiVersionConfig.ID2.getValue());
                    })
                    .body(formData)
                    .retrieve()
                    .toEntity(String.class);
            return null;
        }).when(spyWallet).respondToVerificationID2(Mockito.any(RequestObject.class), Mockito.anyString());

        final int before = awaitStableVerifierCallbacks();

        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () ->
                spyWallet.respondToVerification(
                        SwiyuApiVersionConfig.ID2,
                        verificationDetails,
                        res
                )
        );

        assertThat(errorCode(ex)).isEqualTo(400);
        /* Until find better solution for testing error message content between version tags
        assertThat(errorJson(ex))
                .containsEntry("detail", "authorization_request_missing_error_param")
                .containsEntry("error", "invalid_request")
                .containsEntry("error_code", "authorization_request_missing_error_param");
         */

        awaitNoneVerifierCallback(before);
        verifierManager.verifyState(VerificationStatus.PENDING);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-560",
            summary = "Verification presentation submission is rejected when presentation_submission is invalid",
            description = """
                    This test validates that the Verifier OID4VP endpoint correctly rejects presentation submissions
                    where the presentation_submission field is invalid or malformed. The submission must contain valid
                    descriptor mappings with proper structure for the verifier to accept the presentation.
                    """
    )
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.EDGE_CASE)
    void wrongPresentationSubmission_thenRejected() {
        final CredentialWithDeeplinkResponse response =
                issuerManager.createCredentialOffer("bound_example_sd_jwt");

        final WalletBatchEntry batchEntry =
                wallet.collectOffer(toUri(response.getOfferDeeplink()));
        assertThat(batchEntry.getCredentialOffer()).isNotNull();

        final String deepLink = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversity()
                .create();

        final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(deepLink);
        final String res = batchEntry.createPresentationForSdJwtIndex(0, verificationDetails);

        final int before = awaitStableVerifierCallbacks();

        // Spy wallet to simulate missing presentation_submission
        final Wallet spyWallet = Mockito.spy(wallet);
        Mockito.doAnswer(invocation -> {
            final RequestObject requestObject = invocation.getArgument(0);
            final String token = invocation.getArgument(1);

            final var formData = new LinkedMultiValueMap<String, String>();
            formData.add("vp_token", token);
            formData.add("presentation_submission", "{}");

            spyWallet.getRestClient().post()
                    .uri(spyWallet.getVerifierContext().getContextualizedUri(
                            ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri(requestObject.getResponseUri())
                    ))
                    .headers(headers -> {
                        headers.add(org.springframework.http.HttpHeaders.CONTENT_TYPE,
                                org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE);
                        headers.add("SWIYU-API-Version", SwiyuApiVersionConfig.ID2.getValue());
                    })
                    .body(formData)
                    .retrieve()
                    .toEntity(String.class);
            return null;
        }).when(spyWallet).respondToVerificationID2(Mockito.any(RequestObject.class), Mockito.anyString());

        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () ->
                spyWallet.respondToVerification(
                        SwiyuApiVersionConfig.ID2,
                        verificationDetails,
                        res
                )
        );

        assertThat(errorCode(ex)).isEqualTo(400);
        assertThat(errorJson(ex))
                .containsEntry("detail", "invalid_presentation_submission")
                .containsEntry("error", "invalid_request")
                .containsEntry("error_code", "invalid_presentation_submission");
        assertThat(errorJson(ex).get("error_description"))
                .as("Error description must describe missing presentation submission fields")
                .contains("Invalid presentation submission")
                .contains("Presentation submission id is mandatory")
                .contains("DescriptorDto map cannot be empty");

        awaitOneVerifierCallback(before);
        verifierManager.verifyState(VerificationStatus.FAILED);
    }
}
