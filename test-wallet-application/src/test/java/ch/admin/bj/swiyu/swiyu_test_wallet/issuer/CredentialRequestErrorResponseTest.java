package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.UseWallet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientResponseException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/** Checks the Credential Endpoint error contract on initial collection and renewal. */
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.RENEWAL_PERMISSIVE_EXPERIMENTAL)
@UseWallet(dpop = true, encryption = true, signedMetadata = true)
@Tag(ReportingTags.UCI_I1)
@Tag(ReportingTags.EDGE_CASE)
class CredentialRequestErrorResponseTest extends BaseTest {

    private enum RequestFault {
        MISSING_CONFIGURATION("invalid_credential_request"),
        MALFORMED_JSON("invalid_credential_request"),
        UNKNOWN_CONFIGURATION("unknown_credential_configuration"),
        UNSUPPORTED_IDENTIFIER("invalid_credential_request"),
        MISSING_PROOFS("invalid_proof"),
        EMPTY_PROOFS("invalid_credential_request"),
        MALFORMED_PROOF("invalid_proof"),
        MISSING_NONCE("invalid_proof"),
        INVALID_NONCE("invalid_nonce"),
        INVALID_SIGNATURE("invalid_proof"),
        WRONG_AUDIENCE("invalid_proof"),
        MISSING_RESPONSE_ENCRYPTION("invalid_encryption_parameters");

        private final String expectedError;

        RequestFault(final String expectedError) {
            this.expectedError = expectedError;
        }
    }

    private static Stream<Arguments> requestFaults() {
        return Stream.of(false, true)
                .flatMap(renewal -> Arrays.stream(RequestFault.values())
                        .map(fault -> Arguments.of(renewal, fault)));
    }

    @ParameterizedTest(name = "[{index}] renewal={0}, fault={1}")
    @MethodSource("requestFaults")
    @XrayTest(key = "EIDOMNI-XXX",
            summary = "Credential Issuer returns specific unencrypted errors for invalid collection and renewal requests",
            description = """
                    Given a valid access token and an encrypted Credential Request with DPoP.
                    When the Wallet mutates one request field during initial collection or renewal.
                    Then the Credential Issuer rejects the request with its specific JSON error code,
                    issues no batch and preserves the family.
                    Deviation: the Wallet deliberately sends a malformed or unsupported parameter, proof or nonce.
                    Spec: OID4VCI 1.0 sections 8.2, 8.3.1.2 and F.1; Swiss issuance profile sections 8.2 and 14.5.
                    credential_identifier is unsupported by the Swiss profile and is tested as an invalid request;
                    unknown_credential_identifier is not required for an unsupported identifier-based issuance flow.
                    An empty jwt array violates the request structure requiring a non-empty array.
                    """)
    void credentialRequest_whenWalletSendsInvalidPayload_thenSpecificErrorWithoutIssuance(
            final boolean renewal, final RequestFault fault) throws Exception {
        // Given: only the request payload deviates; transport, token and DPoP remain valid.
        useIssuer(issuer(IssuerVariant.RENEWAL_PERMISSIVE_EXPERIMENTAL));
        final var offer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                CredentialSubjectFixtures.completeEmployeeProfile());
        final var entry = renewal
                ? wallet.collectOffer(toUri(offer.getOfferDeeplink())).duplicate()
                : wallet.prepareOffer(toUri(offer.getOfferDeeplink()));
        if (renewal) {
            entry.generateHolderKeys();
            entry.setCNonce(wallet.collectCNonce(entry));
            entry.createProofs();
        }
        if (fault == RequestFault.MISSING_NONCE) {
            entry.createProofs(null);
        } else if (fault == RequestFault.INVALID_NONCE) {
            entry.createProofs(UUID.randomUUID() + entry.getCNonce().substring(entry.getCNonce().indexOf("::")));
        }
        final var mapper = new ObjectMapper();
        final var payload = (ObjectNode) mapper.readTree(wallet.createCredentialRequestPayload(entry));
        final var proofs = (ObjectNode) payload.get("proofs");
        switch (fault) {
            case MISSING_CONFIGURATION -> payload.remove("credential_configuration_id");
            case UNKNOWN_CONFIGURATION -> payload.put("credential_configuration_id", "unknown-" + UUID.randomUUID());
            case UNSUPPORTED_IDENTIFIER -> {
                payload.remove("credential_configuration_id");
                payload.put("credential_identifier", "unsupported-" + UUID.randomUUID());
            }
            case MISSING_PROOFS -> payload.remove("proofs");
            case EMPTY_PROOFS -> proofs.putArray("jwt");
            case MALFORMED_PROOF -> proofs.putArray("jwt").add("not-a-jwt");
            case INVALID_SIGNATURE -> {
                final var jwt = SignedJWT.parse(proofs.get("jwt").get(0).asString());
                final String signature = jwt.getSignature().toString();
                proofs.putArray("jwt").add(jwt.serialize().substring(0, jwt.serialize().lastIndexOf('.') + 1)
                        + (signature.charAt(0) == 'A' ? 'B' : 'A') + signature.substring(1));
            }
            case WRONG_AUDIENCE -> {
                final var jwt = SignedJWT.parse(proofs.get("jwt").get(0).asString());
                final var claims = new JWTClaimsSet.Builder(jwt.getJWTClaimsSet())
                        .audience("https://wrong-issuer.invalid")
                        .build();
                final var mutated = new SignedJWT(jwt.getHeader(), claims);
                mutated.sign(ECCryptoSupport.createECDSASigner(entry.getHolderKeyPairs().getFirst().getPrivate()));
                proofs.putArray("jwt").add(mutated.serialize());
            }
            case MISSING_RESPONSE_ENCRYPTION -> payload.remove("credential_response_encryption");
            default -> { /* The other mutations operate on the nonce or serialized JSON. */ }
        }
        final String requestPayload = switch (fault) {
            case MALFORMED_JSON -> payload.toString().substring(0, payload.toString().length() - 1);
            default -> payload.toString();
        };
        final var before = issuerManager.getCredentialById(offer.getManagementId());
        awaitStableIssuerCallbacks();
        final var successfulCallbacksBefore = issuerCallbacks().stream()
                .filter(callback -> "ISSUED".equals(callback.getEvent()))
                .toList();

        // When
        final var unexpectedResponse = new AtomicReference<ResponseEntity<String>>();
        final var thrown = catchThrowable(() -> unexpectedResponse.set(
                wallet.postCredentialRequestWithCustomPayload(entry, requestPayload)));
        assertThat(thrown)
                .as("Credential Request must be rejected; returned HTTP status: %s",
                        unexpectedResponse.get() == null ? "none" : unexpectedResponse.get().getStatusCode().value())
                .isInstanceOf(RestClientResponseException.class);
        final var failure = (RestClientResponseException) thrown;

        // Then: no successful issuance or renewal is allowed to escape validation.
        final var after = issuerManager.getCredentialById(offer.getManagementId());
        assertThat(after.getStatus())
                .isEqualTo(before.getStatus());
        assertThat(after.getCredentialOffers())
                .containsExactlyInAnyOrderElementsOf(before.getCredentialOffers());
        assertThat(after.getRenewalRequestCount())
                .isEqualTo(before.getRenewalRequestCount());
        assertThat(after.getRenewalResponseCount())
                .isEqualTo(before.getRenewalResponseCount());
        assertThat(entry.getIssuedCredentials())
                .isEmpty();
        awaitStableIssuerCallbacks();
        assertThat(issuerCallbacks().stream()
                .filter(callback -> "ISSUED".equals(callback.getEvent()))
                .toList())
                .containsExactlyElementsOf(successfulCallbacksBefore);
        assertThat(failure.getStatusCode().value())
                .as("Credential Error Response: %s", failure.getResponseBodyAsString())
                .isEqualTo(400);
        assertThat(failure.getResponseHeaders())
                .isNotNull();
        assertThat(failure.getResponseHeaders().getContentType())
                .isNotNull()
                .matches(contentType -> contentType.isCompatibleWith(MediaType.APPLICATION_JSON));
        final var errorBody = mapper.readTree(failure.getResponseBodyAsString());
        assertThat(errorBody.isObject())
                .as("Credential Error Response is an unencrypted JSON object")
                .isTrue();
        ApiErrorAssert.assertThat((HttpClientErrorException) failure)
                .hasStatus(400)
                .hasError(fault.expectedError);
        assertThat(errorBody.path("error").asString())
                .matches("[\\x00-\\x7F]+");
        assertThat(errorBody.has("credentials"))
                .isFalse();
        assertThat(errorBody.has("transaction_id"))
                .isFalse();
    }
}
