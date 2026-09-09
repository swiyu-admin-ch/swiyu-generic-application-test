package ch.admin.bj.swiyu.swiyu_test_wallet.verifier.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit5.PactConsumerTest;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.V4Pact;
import au.com.dius.pact.core.model.annotations.Pact;
import ch.admin.bj.swiyu.gen.verifier.model.CreateVerificationManagement;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClientResponseException;

import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.pact.VerifierManagementConsumerPactSupport.CONSUMER;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.pact.VerifierManagementConsumerPactSupport.JSON_CONTENT_TYPE_REGEX;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.pact.VerifierManagementConsumerPactSupport.PROVIDER;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.pact.VerifierManagementConsumerPactSupport.RESPONSE_CODE;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.pact.VerifierManagementConsumerPactSupport.VERIFICATION_ID;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.pact.VerifierManagementConsumerPactSupport.WRONG_RESPONSE_CODE;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.pact.VerifierManagementConsumerPactSupport.buildVerifierManager;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.pact.VerifierManagementConsumerPactSupport.invalidVerificationRequestBody;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.pact.VerifierManagementConsumerPactSupport.validVerificationRequest;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.pact.VerifierManagementConsumerPactSupport.validVerificationRequestBody;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.pact.VerifierManagementConsumerPactSupport.verificationResponseBody;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.pact.VerifierManagementConsumerPactSupport.verificationStateParameters;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@PactConsumerTest
@PactTestFor(providerName = PROVIDER, pactVersion = PactSpecVersion.V4)
class VerifierManagementConsumerPactTest {

    private static final String VERIFICATION_PATH = "/management/api/verifications/" + VERIFICATION_ID;
    private static final String DYNAMIC_VERIFICATION_PATH = "/management/api/verifications/${verificationId}";

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact createVerification(final PactDslWithProvider builder) {
        return builder
                .given("verification creation is available", verificationStateParameters())
                .uponReceiving("IF-100 POST creates a verification")
                .method("POST")
                .path("/management/api/verifications")
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(validVerificationRequestBody(), "application/json")
                .willRespondWith()
                .status(200)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(verificationResponseBody("PENDING", false))
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact rejectInvalidVerification(final PactDslWithProvider builder) {
        return builder
                .given("verification creation is available", verificationStateParameters())
                .uponReceiving("IF-100 POST rejects an invalid verification")
                .method("POST")
                .path("/management/api/verifications")
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(invalidVerificationRequestBody(), "application/json")
                .willRespondWith()
                .status(400)
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact getPendingVerification(final PactDslWithProvider builder) {
        return successfulGetInteraction(
                builder,
                "a pending verification exists",
                "IF-100 GET retrieves a pending verification",
                "PENDING",
                false);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact getSuccessfulVerification(final PactDslWithProvider builder) {
        return successfulGetInteraction(
                builder,
                "a successful verification exists",
                "IF-100 GET retrieves a successful verification with wallet result",
                "SUCCESS",
                true);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact getRedirectedVerificationWithResponseCode(final PactDslWithProvider builder) {
        return builder
                .given("a successful redirected verification exists", verificationStateParameters())
                .uponReceiving("IF-100 GET retrieves a redirected verification with its response code")
                .method("GET")
                .pathFromProviderState(DYNAMIC_VERIFICATION_PATH, VERIFICATION_PATH)
                .queryParameterFromProviderState("response_code", "${responseCode}", RESPONSE_CODE.toString())
                .willRespondWith()
                .status(200)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(verificationResponseBody("SUCCESS", true))
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact rejectWrongResponseCode(final PactDslWithProvider builder) {
        return builder
                .given("a successful redirected verification exists", verificationStateParameters())
                .uponReceiving("IF-100 GET rejects a wrong response code")
                .method("GET")
                .pathFromProviderState(DYNAMIC_VERIFICATION_PATH, VERIFICATION_PATH)
                .query("response_code=" + WRONG_RESPONSE_CODE)
                .willRespondWith()
                .status(400)
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact getUnknownVerification(final PactDslWithProvider builder) {
        return builder
                .given("no verification exists", Map.of("verificationId", VERIFICATION_ID.toString()))
                .uponReceiving("IF-100 GET rejects an unknown verification identifier")
                .method("GET")
                .pathFromProviderState(DYNAMIC_VERIFICATION_PATH, VERIFICATION_PATH)
                .willRespondWith()
                .status(404)
                .toPact(V4Pact.class);
    }

    @Test
    @PactTestFor(pactMethod = "createVerification")
    void shouldCreateVerification(final MockServer mockServer) {
        final var response = buildVerifierManager(mockServer).createVerificationRequest(validVerificationRequest());

        assertThat(response.getId()).isEqualTo(VERIFICATION_ID);
        assertThat(response.getState()).isEqualTo(VerificationStatus.PENDING);
    }

    @Test
    @PactTestFor(pactMethod = "rejectInvalidVerification")
    void shouldRejectInvalidVerification(final MockServer mockServer) {
        assertStatus(
                () -> buildVerifierManager(mockServer)
                        .createVerificationRequest(new CreateVerificationManagement()),
                400);
    }

    @Test
    @PactTestFor(pactMethod = "getPendingVerification")
    void shouldRetrievePendingVerification(final MockServer mockServer) {
        assertThat(buildVerifierManager(mockServer).getVerificationById(VERIFICATION_ID).getState())
                .isEqualTo(VerificationStatus.PENDING);
    }

    @Test
    @PactTestFor(pactMethod = "getSuccessfulVerification")
    void shouldRetrieveSuccessfulVerificationWithWalletResult(final MockServer mockServer) {
        final var response = buildVerifierManager(mockServer).getVerificationById(VERIFICATION_ID);

        assertThat(response.getState()).isEqualTo(VerificationStatus.SUCCESS);
        assertThat(response.getWalletResponse().getCredentialSubjectData())
                .containsKey("VerifiableCredential");
    }

    @Test
    @PactTestFor(pactMethod = "getRedirectedVerificationWithResponseCode")
    void shouldRetrieveRedirectedVerificationWithResponseCode(final MockServer mockServer) {
        assertThat(buildVerifierManager(mockServer)
                .getVerificationById(VERIFICATION_ID, RESPONSE_CODE)
                .getState()).isEqualTo(VerificationStatus.SUCCESS);
    }

    @Test
    @PactTestFor(pactMethod = "rejectWrongResponseCode")
    void shouldRejectWrongResponseCode(final MockServer mockServer) {
        assertStatus(
                () -> buildVerifierManager(mockServer)
                        .getVerificationById(VERIFICATION_ID, WRONG_RESPONSE_CODE),
                400);
    }

    @Test
    @PactTestFor(pactMethod = "getUnknownVerification")
    void shouldRejectUnknownVerificationIdentifier(final MockServer mockServer) {
        assertStatus(() -> buildVerifierManager(mockServer).getVerificationById(VERIFICATION_ID), 404);
    }

    private static V4Pact successfulGetInteraction(
            final PactDslWithProvider builder,
            final String providerState,
            final String description,
            final String state,
            final boolean withWalletResponse) {
        return builder
                .given(providerState, verificationStateParameters())
                .uponReceiving(description)
                .method("GET")
                .pathFromProviderState(DYNAMIC_VERIFICATION_PATH, VERIFICATION_PATH)
                .willRespondWith()
                .status(200)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(verificationResponseBody(state, withWalletResponse))
                .toPact(V4Pact.class);
    }

    private static void assertStatus(final Runnable request, final int expectedStatus) {
        assertThatThrownBy(request::run)
                .isInstanceOf(RestClientResponseException.class)
                .satisfies(exception -> assertThat(((RestClientResponseException) exception).getStatusCode().value())
                        .isEqualTo(expectedStatus));
    }
}
