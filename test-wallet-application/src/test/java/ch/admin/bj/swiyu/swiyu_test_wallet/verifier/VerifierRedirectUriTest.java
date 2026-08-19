package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierRedirectUriTest extends BaseTest {

    private static final String REDIRECT_BASE_URI = "https://business-verifier.example/callback";

    @Test
    @XrayTest(
            key = "EIDOMNI-731",
            summary = "Holder is redirected to the Business Verifier after a successful presentation",
            description = """
                    This test validates the complete session-fixation mitigation flow. The Business Verifier
                    provides a redirect_uri with a session nonce, the fake Wallet submits a valid presentation,
                    receives HTTP 200 application/json, reads the returned redirect_uri and uses its response_code
                    to retrieve the successful verification result.
                    """
    )
    @Tag(ReportingTags.UCV_M1)
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.UCV_M3)
    @Tag(ReportingTags.HAPPY_PATH)
    void successfulPresentation_withRedirectUri_thenHolderCanRetrieveResultWithResponseCode() {
        // Given – credential issued to the fake Wallet
        final CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialOffer("bound_example_sd_jwt");
        final WalletBatchEntry walletEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        // Given – Business Verifier binds its browser session to the verification
        final String sessionNonce = UUID.randomUUID().toString();
        final URI requestedRedirectUri = redirectUri(sessionNonce);
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL()
                .redirectUri(requestedRedirectUri)
                .createManagementResponse();
        final RequestObject requestObject =
                wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = walletEntry.createPresentationForSdJwtIndex(0, requestObject);

        // When – Wallet submits the Authorization Response and follows the returned redirect target
        final URI holderRedirectUri = wallet.respondToVerification(requestObject, presentation)
                .orElseThrow(() -> new AssertionError("Verifier must return redirect_uri"));
        final UUID responseCode = responseCodeFrom(holderRedirectUri);

        // Then – the original callback and session binding are preserved
        assertRedirectUri(holderRedirectUri, requestedRedirectUri, sessionNonce);
        assertThat(responseCode.version())
                .as("response_code must be a cryptographically generated UUID v4")
                .isEqualTo(4);

        // Then – Business Verifier presents response_code to retrieve the matching terminal result
        final ManagementResponse result =
                verifierManager.getVerificationById(verification.getId(), responseCode);
        assertThat(result.getState()).isEqualTo(VerificationStatus.SUCCESS);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-732",
            summary = "Redirect responses remain bound to their verification session",
            description = """
                    These security edge cases validate that every response_code is fresh, required for a
                    redirect-enabled verification and bound to exactly one verification. Omitting the code or reusing
                    the response_code from another browser session must be rejected. A relative redirect_uri must also
                    be rejected during verification creation.
                    """
    )
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.UCV_M3)
    @Tag(ReportingTags.EDGE_CASE)
    void redirectEnabledVerifications_withMissingOrCrossSessionResponseCode_thenRejectResultAccess() {
        // Given – a credential and two independent redirect-enabled browser sessions
        final CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialOffer("bound_example_sd_jwt");
        final WalletBatchEntry walletEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final ManagementResponse firstVerification = createRedirectEnabledVerification(UUID.randomUUID().toString());
        final ManagementResponse secondVerification = createRedirectEnabledVerification(UUID.randomUUID().toString());
        final RequestObject firstRequest =
                wallet.getVerificationRequestObject(firstVerification.getVerificationDeeplink());
        final RequestObject secondRequest =
                wallet.getVerificationRequestObject(secondVerification.getVerificationDeeplink());
        final String firstPresentation = walletEntry.createPresentationForSdJwtIndex(0, firstRequest);
        final String secondPresentation = walletEntry.createPresentationForSdJwtIndex(0, secondRequest);

        // When – Wallet completes both verifications and receives two redirect targets
        final URI firstRedirect = wallet.respondToVerification(firstRequest, firstPresentation)
                .orElseThrow(() -> new AssertionError("Verifier must return redirect_uri for first response"));
        final URI secondRedirect = wallet.respondToVerification(secondRequest, secondPresentation)
                .orElseThrow(() -> new AssertionError("Verifier must return redirect_uri for second response"));
        final UUID firstResponseCode = responseCodeFrom(firstRedirect);
        final UUID secondResponseCode = responseCodeFrom(secondRedirect);

        // Then – response codes are fresh per verification
        assertThat(firstResponseCode).isNotEqualTo(secondResponseCode);

        // When – result retrieval omits the code required for a redirect-enabled session
        final HttpClientErrorException missingCodeException = assertThrows(HttpClientErrorException.class, () ->
                verifierManager.getVerificationById(firstVerification.getId()));

        // Then – access without the session binding is rejected
        ApiErrorAssert.assertThat(missingCodeException).hasStatus(400);

        // When – an attacker substitutes the response_code from the other browser session
        final HttpClientErrorException substitutedCodeException = assertThrows(HttpClientErrorException.class, () ->
                verifierManager.getVerificationById(firstVerification.getId(), secondResponseCode));

        // Then – the mismatched session binding is rejected while the legitimate code still works
        ApiErrorAssert.assertThat(substitutedCodeException).hasStatus(400);
        final ManagementResponse legitimateResult =
                verifierManager.getVerificationById(firstVerification.getId(), firstResponseCode);
        assertThat(legitimateResult.getState()).isEqualTo(VerificationStatus.SUCCESS);

        // When – a Business Verifier provides a relative callback URI
        final URI relativeRedirectUri = URI.create("/callback?session_nonce=" + UUID.randomUUID());
        final HttpClientErrorException invalidRedirectException = assertThrows(HttpClientErrorException.class, () ->
                verifierManager.verificationRequest()
                        .acceptedIssuerDid(issuerConfig.getIssuerDid())
                        .withUniversityDCQL()
                        .redirectUri(relativeRedirectUri)
                        .createManagementResponse());

        // Then – the invalid redirect target is rejected at the management boundary
        ApiErrorAssert.assertThat(invalidRedirectException).hasStatus(400);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1248",
            summary = "Redirect URI remains optional and supports Authorization Error Responses",
            description = """
                    Using a common setup, this test compares an Authorization Error Response for a redirect-enabled
                    verification with a successful legacy verification. An Error Response may omit redirect_uri; when
                    present its response_code is used to retrieve the failed result. When omitted, the Wallet performs
                    no further action. Clients without redirect_uri remain backward compatible.
                    """
    )
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.UCV_M3)
    @Tag(ReportingTags.EDGE_CASE)
    void redirectUri_withAuthorizationErrorAndLegacyClient_thenPreserveOptionalBehavior() {
        // Given – one credential and two verifications sharing the same issuer configuration
        final CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialOffer("bound_example_sd_jwt");
        final WalletBatchEntry walletEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        final String errorSessionNonce = UUID.randomUUID().toString();
        final URI requestedErrorRedirect = redirectUri(errorSessionNonce);
        final ManagementResponse failedVerification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL()
                .redirectUri(requestedErrorRedirect)
                .createManagementResponse();
        final ManagementResponse legacyVerification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL()
                .createManagementResponse();

        final RequestObject failedRequest =
                wallet.getVerificationRequestObject(failedVerification.getVerificationDeeplink());
        final RequestObject legacyRequest =
                wallet.getVerificationRequestObject(legacyVerification.getVerificationDeeplink());
        final String legacyPresentation = walletEntry.createPresentationForSdJwtIndex(0, legacyRequest);

        // When – the fake Wallet declines one verification and completes the legacy verification
        final var errorRedirect = wallet.respondToVerificationWithError(
                failedRequest, "access_denied", "Holder declined the verification");
        final var legacyRedirect = wallet.respondToVerification(legacyRequest, legacyPresentation);
        final ManagementResponse legacyResult = verifierManager.getVerificationById(legacyVerification.getId());

        // Then – legacy behavior is preserved without redirect_uri or response_code
        assertThat(legacyRedirect).isEmpty();
        assertThat(legacyResult.getState()).isEqualTo(VerificationStatus.SUCCESS);

        // Then – the Wallet follows the optional error redirect only when the Verifier returns one
        if (errorRedirect.isPresent()) {
            final URI holderErrorRedirect = errorRedirect.orElseThrow();
            assertRedirectUri(holderErrorRedirect, requestedErrorRedirect, errorSessionNonce);
            final ManagementResponse failedResult = verifierManager.getVerificationById(
                    failedVerification.getId(), responseCodeFrom(holderErrorRedirect));
            assertThat(failedResult.getState()).isEqualTo(VerificationStatus.FAILED);
        }
    }

    private ManagementResponse createRedirectEnabledVerification(String sessionNonce) {
        return verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL()
                .redirectUri(redirectUri(sessionNonce))
                .createManagementResponse();
    }

    private static URI redirectUri(String sessionNonce) {
        return UriComponentsBuilder.fromUriString(REDIRECT_BASE_URI)
                .queryParam("session_nonce", sessionNonce)
                .build()
                .toUri();
    }

    private static UUID responseCodeFrom(URI redirectUri) {
        final String responseCode = UriComponentsBuilder.fromUri(redirectUri)
                .build()
                .getQueryParams()
                .getFirst("response_code");
        assertThat(responseCode)
                .as("redirect_uri must contain response_code")
                .isNotBlank();
        return UUID.fromString(responseCode);
    }

    private static void assertRedirectUri(URI actual, URI requested, String sessionNonce) {
        assertThat(actual.getScheme()).isEqualTo(requested.getScheme());
        assertThat(actual.getAuthority()).isEqualTo(requested.getAuthority());
        assertThat(actual.getPath()).isEqualTo(requested.getPath());
        assertThat(UriComponentsBuilder.fromUri(actual).build().getQueryParams().getFirst("session_nonce"))
                .isEqualTo(sessionNonce);
    }
}
