package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager.VerificationRequestBuilder;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Map;
import java.util.UUID;

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

}
