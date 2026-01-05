package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.testcontainers.containers.GenericContainer;

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
                    This test validates the end-to-end flow for deeplink verification, 

                    Steps:
                    1. The verifier initiates a verification request following the OID4VP flow.
                    2. The wallet retrieves verification details 
                    """
    )
    @Tag("ucv_m1")
    @Tag("ucv_m1b")
    @Tag("happy_path")
    void verifierProvidesDeeplink() {
        final ManagementResponse deeplink = verifierManager.verificationRequest().acceptedIssuerDid(UUID.randomUUID().toString()).createManagementResponse();
        assertThat(deeplink.getVerificationDeeplink())
                .isNotNull()
                .startsWith("swiyu-verify://");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-557",
            summary = "Successful deeplink creation for verification request"
    )
    @Tag("ucv_m1")
    @Tag("edge_case")
    void managementCreateVerification_missingPresentationDefinition_thenRejected() {
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () ->
                verifierManager.verificationRequest().acceptedIssuerDid(UUID.randomUUID().toString()).presentationDefinition(null).createManagementResponse()
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
            summary = "Successful deeplink creation for verification request"
    )
    @Tag("ucv_m3")
    @Tag("edge_case")
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
            summary = "Successful deeplink creation for verification request"
    )
    @Tag("ucv_o2")
    @Tag("edge_case")
    void missingPresentationSubmission_thenRejected() {
        final CredentialWithDeeplinkResponse response =
                issuerManager.createCredentialOffer("university_example_sd_jwt");

        final WalletEntry entry =
                wallet.collectOffer(SwiyuApiVersionConfig.ID2, toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        final String deepLink = verifierManager.verificationRequest()
                .acceptedIssuerDid(entry.getIssuerDid())
                .withUniversity()
                .create();

        final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(deepLink);
        final String res = entry.createPresentationForSdJwt(entry.getVerifiableCredential(), verificationDetails);

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
        assertThat(errorJson(ex))
                .containsExactlyInAnyOrderEntriesOf(Map.of(
                        "detail", "authorization_request_missing_error_param",
                        "error", "invalid_request",
                        "error_code", "authorization_request_missing_error_param",
                        "error_description", "Incomplete submission for ID2, must contain vp_token and presentation_submission"
                ));

        awaitNoneVerifierCallback(before);
        verifierManager.verifyState(VerificationStatus.PENDING);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-560",
            summary = "Successful deeplink creation for verification request"
    )
    @Tag("ucv_o2")
    @Tag("edge_case")
    void wrongPresentationSubmission_thenRejected() {
        final CredentialWithDeeplinkResponse response =
                issuerManager.createCredentialOffer("university_example_sd_jwt");

        final WalletEntry entry =
                wallet.collectOffer(SwiyuApiVersionConfig.ID2, toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        final String deepLink = verifierManager.verificationRequest()
                .acceptedIssuerDid(entry.getIssuerDid())
                .withUniversity()
                .create();

        final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(deepLink);
        final String res = entry.createPresentationForSdJwt(entry.getVerifiableCredential(), verificationDetails);

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
