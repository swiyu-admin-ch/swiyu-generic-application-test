package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.JwtProof;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.function.UnaryOperator;
import java.util.stream.IntStream;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class IssuerKeyProofValidationTest extends BaseTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final Duration CLOCK_SKEW_BEYOND_TOLERANCE = Duration.ofHours(1);
    private static final String INVALID_NONCE = "Invalid nonce claim in proof JWT";
    private static final String ISSUE_TIME_OUTSIDE_WINDOW = "Holder Binding proof was not issued at an acceptable time";

    @ParameterizedTest(name = "[{index}] reject {0}")
    @EnumSource(KeyProofDeviation.class)
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Issuer rejects a key proof that is not bound to this Credential Issuer and c_nonce",
            description = """
                    Given a pre-authorized offer for a holder-bound credential, an access token and a fresh c_nonce.
                    When the wallet sends the Credential Request with jwt key proofs signed by the holder keys
                    but with exactly one deviation: the aud of another Credential Issuer, a nonce the Issuer never
                    provided, no nonce at all, or an iat outside the accepted window.
                    Then the Issuer rejects the request with HTTP 400 invalid_proof, or invalid_nonce for an unknown
                    c_nonce, and issues no credential.
                    Deviation: one key proof claim differs from the Credential Issuer's required value or freshness policy.
                    Spec: OID4VCI 1.0 §7, §8.2, §8.3.1.2 and Appendix F.1, F.4.
                    """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    void credentialRequest_whenKeyProofDeviates_thenRejectedWithoutIssuance(final KeyProofDeviation deviation) {
        // Given
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
        );
        final WalletBatchEntry batchEntry = wallet.prepareOffer(toUri(offer.getOfferDeeplink()));
        final CredentialStatusType stateBefore = issuerManager.getStatusById(offer.getManagementId()).getStatus();
        final List<String> keyProofs = IntStream.range(0, batchEntry.getHolderKeyPairs().size())
                .mapToObj(index -> deviation.apply(JwtProof.builder().credentialIssuerURI(
                                        batchEntry.getIssuerMetadata().getCredentialIssuer()).cNonce(
                                        batchEntry.getCNonce()
                                )
                                .keyPair(batchEntry.getHolderKeyPairs().get(index)).publicJwk(batchEntry.getHolderPublicKeys().get(index)))
                        .build().toJwt())
                .toList();
        final ObjectNode credentialRequest = credentialRequest(batchEntry);
        credentialRequest.withObject("proofs").set("jwt", JSON.valueToTree(keyProofs));

        // When
        final HttpClientErrorException exception = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.postCredentialRequestWithCustomPayload(batchEntry, JSON.writeValueAsString(credentialRequest))
        );

        // Then
        assertThat(issuerManager.getStatusById(offer.getManagementId()).getStatus())
                .as("A rejected key proof must not issue a credential")
                .isEqualTo(stateBefore);
        ApiErrorAssert.assertThat(exception)
                .hasStatus(400)
                .hasError(deviation == KeyProofDeviation.NONCE_NOT_PROVIDED_BY_ISSUER ? "invalid_nonce" : "invalid_proof");
        assertThat(exception.getResponseBodyAsString())
                .contains(deviation.errorDescription());
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Issuer rejects a Credential Request for an unknown credential configuration",
            description = """
                    Given a pre-authorized offer, an access token and valid key proofs.
                    When the wallet sends the Credential Request with a credential_configuration_id that the Issuer
                    metadata does not list.
                    Then the Issuer rejects the request with HTTP 400 unknown_credential_configuration and issues no
                    credential.
                    Deviation: credential_configuration_id is not advertised in the Credential Issuer metadata.
                    Spec: OID4VCI 1.0 §8.2 and §8.3.1.2.
                    """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    void credentialRequest_whenCredentialConfigurationIsUnknown_thenRejectedWithoutIssuance() {
        // Given
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
        );
        final WalletBatchEntry batchEntry = wallet.prepareOffer(toUri(offer.getOfferDeeplink()));
        final CredentialStatusType stateBefore = issuerManager.getStatusById(offer.getManagementId()).getStatus();
        final ObjectNode credentialRequest = credentialRequest(batchEntry);
        // Deviation: a credential_configuration_id the Issuer metadata does not list.
        credentialRequest.put("credential_configuration_id", "unknown_credential_configuration_sd_jwt");

        // When
        final HttpClientErrorException exception = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.postCredentialRequestWithCustomPayload(batchEntry, JSON.writeValueAsString(credentialRequest))
        );

        // Then
        assertThat(issuerManager.getStatusById(offer.getManagementId()).getStatus())
                .as("A request for an unknown credential configuration must not issue a credential")
                .isEqualTo(stateBefore);
        ApiErrorAssert.assertThat(exception)
                .hasStatus(400)
                .hasError("unknown_credential_configuration");
    }

    private ObjectNode credentialRequest(final WalletBatchEntry batchEntry) {
        return (ObjectNode) JSON.readTree(wallet.createCredentialRequestPayload(batchEntry));
    }

    private enum KeyProofDeviation {
        /** Deviation: aud names another Credential Issuer than the one that receives the proof. */
        AUDIENCE_OF_ANOTHER_ISSUER(
                "Audience claim is missing or incorrect",
                proof -> proof.withAudience("https://other-issuer.example.com")
        ),
        /** Deviation: nonce is not a c_nonce the Credential Issuer provided. */
        NONCE_NOT_PROVIDED_BY_ISSUER(
                INVALID_NONCE,
                proof -> proof.withNonce("nonce-not-provided-by-issuer")
        ),
        /** Deviation: no nonce, although the Credential Issuer has a Nonce Endpoint. */
        WITHOUT_NONCE(
                INVALID_NONCE,
                JwtProof.JwtProofBuilder::withoutNonce
        ),
        /** Deviation: iat is far in the past, before the c_nonce was even provided. */
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
        private final UnaryOperator<JwtProof.JwtProofBuilder> deviation;

        KeyProofDeviation(final String errorDescription, final UnaryOperator<JwtProof.JwtProofBuilder> deviation) {
            this.expectedDescription = errorDescription;
            this.deviation = deviation;
        }

        String errorDescription() {
            return expectedDescription;
        }

        JwtProof.JwtProofBuilder apply(final JwtProof.JwtProofBuilder proof) {
            return deviation.apply(proof);
        }
    }
}
