package ch.admin.bj.swiyu.swiyu_test_wallet.security;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.UseWallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact.DpopProof;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto.Sha256Base64Url;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpStatusCodeException;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.function.UnaryOperator;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseWallet(dpop = true)
class DPoPProofValidationTest extends BaseTest {

    private static final Duration CLOCK_SKEW_BEYOND_TOLERANCE = Duration.ofHours(1);
    private static final String ISSUE_TIME_OUTSIDE_WINDOW = "Issue time is not in an acceptable window; +/-10";

    @ParameterizedTest(name = "[{index}] reject {0}")
    @EnumSource(DpopDeviation.class)
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Issuer rejects a DPoP proof that is not bound to the credential request",
            description = """
                    Given a DPoP-bound access token and a fresh DPoP nonce from the Credential Issuer.
                    When the wallet sends the Credential Request with a DPoP proof signed by the registered DPoP key
                    but with exactly one deviation: another HTTP method in htm, or an iat outside the accepted window.
                    Then the Issuer rejects the request with HTTP 401 invalid_dpop_proof and issues no credential.
                    Deviation: One DPoP claim differs from the HTTP request, access token or accepted freshness policy.
                    Spec: RFC 9449 §4.2, §4.3 and §11.1; Swiss issuance profile §8.2.
                    """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    void credentialRequest_whenDpopProofDeviates_thenRejectedWithoutIssuance(final DpopDeviation deviation) {
        // Given
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
        );
        final WalletBatchEntry batchEntry = wallet.prepareOffer(toUri(offer.getOfferDeeplink()));
        final URI credentialUri = batchEntry.getIssuerCredentialUri();
        final CredentialStatusType stateBefore = issuerManager.getStatusById(offer.getManagementId()).getStatus();
        final String dpopProof = deviation.apply(DpopProof.forRequest("POST", credentialUri.toString())
                        .nonce(wallet.collectDPoPNonce(batchEntry))
                        .accessToken(batchEntry.getToken().getAccessToken())
                        .signedWith(wallet.getDpopKeyPair(), wallet.getDpopPublicKey()))
                .build();

        // When
        final HttpClientErrorException exception = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.postCredentialRequestWithCustomDPoP(batchEntry, dpopProof, credentialUri)
        );

        // Then
        ApiErrorAssert.assertThat(exception)
                .hasStatus(401)
                .hasError("invalid_dpop_proof")
                .hasErrorDescription(deviation.errorDescription());
        assertThat(issuerManager.getStatusById(offer.getManagementId()).getStatus())
                .as("A rejected DPoP proof must not issue a credential")
                .isEqualTo(stateBefore);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Issuer rejects a DPoP proof whose ath is not the hash of the access token",
            description = """
                    Given a DPoP-bound access token and a fresh DPoP nonce from the Credential Issuer.
                    When the wallet sends the Credential Request with a DPoP proof whose ath is the hash of another
                    access token, so the proof is not bound to the presented token.
                    Then the Issuer rejects the request with HTTP 401 invalid_dpop_proof and issues no credential,
                    instead of answering HTTP 500 because the DpopValidationException is not mapped.
                    Deviation: One DPoP claim differs from the HTTP request, access token or accepted freshness policy.
                    Spec: RFC 9449 §4.2, §4.3 and §7.1.
                    """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    void credentialRequest_whenDpopAthIsOfAnotherAccessToken_thenRejectedWithoutIssuance() {
        // Given
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
        );
        final WalletBatchEntry batchEntry = wallet.prepareOffer(toUri(offer.getOfferDeeplink()));
        final URI credentialUri = batchEntry.getIssuerCredentialUri();
        final CredentialStatusType stateBefore = issuerManager.getStatusById(offer.getManagementId()).getStatus();
        final String dpopProof = DpopProof.forRequest("POST", credentialUri.toString())
                        .nonce(wallet.collectDPoPNonce(batchEntry))
                        .accessToken(batchEntry.getToken().getAccessToken())
                        .signedWith(wallet.getDpopKeyPair(), wallet.getDpopPublicKey())
                        .withAth(Sha256Base64Url.ofUsAscii("another-access-token"))
                .build();

        // When
        final HttpStatusCodeException exception = assertThrows(
                HttpStatusCodeException.class,
                () -> wallet.postCredentialRequestWithCustomDPoP(batchEntry, dpopProof, credentialUri)
        );

        // Then
        assertThat(issuerManager.getStatusById(offer.getManagementId()).getStatus())
                .as("A rejected DPoP proof must not issue a credential")
                .isEqualTo(stateBefore);
        assertThat(exception.getStatusCode().value())
                .isEqualTo(401);
        ApiErrorAssert.assertThat((HttpClientErrorException) exception)
                .hasStatus(401)
                .hasError("invalid_dpop_proof")
                .hasErrorDescription("Access token mismatch. ath must be base64url-encoded SHA-256 hash of the ASCII encoding of the associated access token's value");
    }

    private enum DpopDeviation {
        /** Deviation: htm names another HTTP method than the POST the proof is sent with. */
        HTM_OF_ANOTHER_METHOD(
                "HTTP method mismatch between DPoP and request",
                proof -> proof.withHtm("GET")
        ),
        /** Deviation: iat is far in the past, so the proof is not fresh. */
        ISSUED_AT_IN_THE_PAST(
                ISSUE_TIME_OUTSIDE_WINDOW,
                proof -> proof.withIssuedAt(Instant.now().minus(CLOCK_SKEW_BEYOND_TOLERANCE))
        ),
        /** Deviation: iat is far in the future. */
        ISSUED_AT_IN_THE_FUTURE(
                ISSUE_TIME_OUTSIDE_WINDOW,
                proof -> proof.withIssuedAt(Instant.now().plus(CLOCK_SKEW_BEYOND_TOLERANCE))
        );

        private final String expectedDescription;
        private final UnaryOperator<DpopProof.Builder> deviation;

        DpopDeviation(final String errorDescription, final UnaryOperator<DpopProof.Builder> deviation) {
            this.expectedDescription = errorDescription;
            this.deviation = deviation;
        }

        String errorDescription() {
            return expectedDescription;
        }

        DpopProof.Builder apply(final DpopProof.Builder proof) {
            return deviation.apply(proof);
        }
    }
}
