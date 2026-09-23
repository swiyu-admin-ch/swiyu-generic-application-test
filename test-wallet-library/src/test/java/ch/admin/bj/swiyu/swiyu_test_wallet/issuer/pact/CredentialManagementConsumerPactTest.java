package ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.LambdaDsl;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit5.PactConsumerTest;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.V4Pact;
import au.com.dius.pact.core.model.annotations.Pact;
import ch.admin.bj.swiyu.gen.issuer.model.CreateCredentialOfferRequest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClientResponseException;

import java.util.List;
import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.CONSUMER;
import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.JSON_CONTENT_TYPE_REGEX;
import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.MANAGEMENT_ID;
import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.OFFER_ID;
import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.PROVIDER;
import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.buildBusinessIssuer;
import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.credentialCreationRequestBody;
import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.credentialCreationResponseBody;
import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.credentialManagementResponseBody;
import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.credentialOfferRequest;
import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.credentialOfferResponseBody;
import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.statusResponseBody;
import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.updateStatusResponseBody;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@PactConsumerTest
@PactTestFor(providerName = PROVIDER, pactVersion = PactSpecVersion.V4)
class CredentialManagementConsumerPactTest {

    private static final String MANAGEMENT_PATH = "/management/api/credentials/" + MANAGEMENT_ID;
    private static final String DYNAMIC_MANAGEMENT_PATH = "/management/api/credentials/${managementId}";
    private static final String OFFER_PATH = MANAGEMENT_PATH + "/offers/" + OFFER_ID;
    private static final String DYNAMIC_OFFER_PATH = DYNAMIC_MANAGEMENT_PATH + "/offers/${offerId}";

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact createCredentialOffer(final PactDslWithProvider builder) {
        return builder
                .given("credential offer creation is available", stateParameters())
                .uponReceiving("IF-114 POST creates a credential offer")
                .method("POST")
                .path("/management/api/credentials")
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(credentialCreationRequestBody(false))
                .willRespondWith()
                .status(200)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(credentialCreationResponseBody())
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact rejectInvalidCredentialOffer(final PactDslWithProvider builder) {
        return builder
                .given("credential offer creation is available", stateParameters())
                .uponReceiving("IF-114 POST rejects an invalid credential offer")
                .method("POST")
                .path("/management/api/credentials")
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(LambdaDsl.newJsonBody(body -> body
                        .array("metadata_credential_supported_id")
                        .nullValue("credential_subject_data")
                        .nullValue("credential_metadata")
                        .nullValue("offer_validity_seconds")
                        .nullValue("deferred_offer_validity_seconds")
                        .nullValue("credential_valid_until")
                        .nullValue("credential_valid_from")
                        .array("status_lists")
                        .nullValue("configuration_override")).build())
                .willRespondWith()
                // The issuer maps request-body bean-validation failures (here: empty
                // metadata_credential_supported_id) to 422 UNPROCESSABLE_ENTITY via
                // DefaultExceptionHandler.handleMethodArgumentNotValid. Service-level rejections
                // of a well-formed body (see rejectUpdateOfNonDeferredCredential) still return 400.
                .status(422)
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact getCredentialManagement(final PactDslWithProvider builder) {
        return builder
                .given("an offered credential management exists", stateParameters())
                .uponReceiving("IF-114 GET retrieves credential management")
                .method("GET")
                .pathFromProviderState(DYNAMIC_MANAGEMENT_PATH, MANAGEMENT_PATH)
                .willRespondWith()
                .status(200)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(credentialManagementResponseBody())
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact getCredentialOffer(final PactDslWithProvider builder) {
        return builder
                .given("an offered credential management exists", stateParameters())
                .uponReceiving("IF-114 GET retrieves a credential offer")
                .method("GET")
                .pathFromProviderState(DYNAMIC_OFFER_PATH, OFFER_PATH)
                .willRespondWith()
                .status(200)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(credentialOfferResponseBody("OFFERED"))
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact getCredentialManagementStatus(final PactDslWithProvider builder) {
        return builder
                .given("an offered credential management exists", stateParameters())
                .uponReceiving("IF-114 GET retrieves credential management status")
                .method("GET")
                .pathFromProviderState(DYNAMIC_MANAGEMENT_PATH + "/status", MANAGEMENT_PATH + "/status")
                .willRespondWith()
                .status(200)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(statusResponseBody("OFFERED"))
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact getCredentialOfferStatus(final PactDslWithProvider builder) {
        return builder
                .given("an offered credential management exists", stateParameters())
                .uponReceiving("IF-114 GET retrieves credential offer status")
                .method("GET")
                .pathFromProviderState(DYNAMIC_OFFER_PATH + "/status", OFFER_PATH + "/status")
                .willRespondWith()
                .status(200)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(statusResponseBody("OFFERED"))
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact updateDeferredCredential(final PactDslWithProvider builder) {
        return builder
                .given("a deferred credential management exists", stateParameters())
                .uponReceiving("IF-114 PATCH updates a deferred credential")
                .method("PATCH")
                .pathFromProviderState(DYNAMIC_MANAGEMENT_PATH, MANAGEMENT_PATH)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(LambdaDsl.newJsonBody(body -> body
                        .stringValue("firstName", "John")
                        .stringValue("lastName", "Doe")
                        .stringValue("dateOfBirth", "2000-01-01")).build())
                .willRespondWith()
                .status(200)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(updateStatusResponseBody("READY"))
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact rejectUpdateOfNonDeferredCredential(final PactDslWithProvider builder) {
        return builder
                .given("an offered credential management exists", stateParameters())
                .uponReceiving("IF-114 PATCH rejects an update for a non deferred credential")
                .method("PATCH")
                .pathFromProviderState(DYNAMIC_MANAGEMENT_PATH, MANAGEMENT_PATH)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(LambdaDsl.newJsonBody(body -> body.stringValue("firstName", "John")).build())
                .willRespondWith()
                .status(400)
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact cancelCredential(final PactDslWithProvider builder) {
        return builder
                .given("an offered credential management exists", stateParameters())
                .uponReceiving("IF-114 PATCH cancels a credential")
                .method("PATCH")
                .pathFromProviderState(DYNAMIC_MANAGEMENT_PATH + "/status", MANAGEMENT_PATH + "/status")
                .query("credentialStatus=CANCELLED")
                .willRespondWith()
                .status(200)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(updateStatusResponseBody("CANCELLED"))
                .toPact(V4Pact.class);
    }

    @Test
    @PactTestFor(pactMethod = "createCredentialOffer")
    void shouldCreateCredentialOffer(final MockServer mockServer) {
        final var response = buildBusinessIssuer(mockServer).createCredential(credentialOfferRequest(false));

        assertThat(response.getManagementId()).isEqualTo(MANAGEMENT_ID);
        assertThat(response.getOfferId()).isEqualTo(OFFER_ID);
    }

    @Test
    @PactTestFor(pactMethod = "rejectInvalidCredentialOffer")
    void shouldRejectInvalidCredentialOffer(final MockServer mockServer) {
        final var invalidRequest = new CreateCredentialOfferRequest()
                .metadataCredentialSupportedId(List.of());

        assertClientError(() -> buildBusinessIssuer(mockServer).createCredential(invalidRequest), 422);
    }

    @Test
    @PactTestFor(pactMethod = "getCredentialManagement")
    void shouldRetrieveCredentialManagement(final MockServer mockServer) {
        final var response = buildBusinessIssuer(mockServer).getCredentialById(MANAGEMENT_ID);

        assertThat(response.getId()).isEqualTo(MANAGEMENT_ID);
        assertThat(response.getStatus()).isEqualTo(CredentialStatusType.OFFERED);
        assertThat(response.getCredentialOffers()).hasSize(1);
    }

    @Test
    @PactTestFor(pactMethod = "getCredentialOffer")
    void shouldRetrieveCredentialOffer(final MockServer mockServer) {
        final var response = buildBusinessIssuer(mockServer).getCredentialOfferById(MANAGEMENT_ID, OFFER_ID);

        assertThat(response.getStatus()).isEqualTo(CredentialStatusType.OFFERED);
        assertThat(response.getMetadataCredentialSupportedId()).containsExactly("test");
    }

    @Test
    @PactTestFor(pactMethod = "getCredentialManagementStatus")
    void shouldRetrieveCredentialManagementStatus(final MockServer mockServer) {
        assertThat(buildBusinessIssuer(mockServer).getStatusById(MANAGEMENT_ID).getStatus())
                .isEqualTo(CredentialStatusType.OFFERED);
    }

    @Test
    @PactTestFor(pactMethod = "getCredentialOfferStatus")
    void shouldRetrieveCredentialOfferStatus(final MockServer mockServer) {
        assertThat(buildBusinessIssuer(mockServer)
                .getCredentialOfferStatusById(MANAGEMENT_ID, OFFER_ID)
                .getStatus()).isEqualTo(CredentialStatusType.OFFERED);
    }

    @Test
    @PactTestFor(pactMethod = "updateDeferredCredential")
    void shouldUpdateDeferredCredential(final MockServer mockServer) {
        final var response = buildBusinessIssuer(mockServer).updateCredentialForDeferredFlowRequestCreation(
                MANAGEMENT_ID,
                Map.of(
                        "firstName", "John",
                        "lastName", "Doe",
                        "dateOfBirth", "2000-01-01"));

        assertThat(response.getStatus()).isEqualTo(CredentialStatusType.READY);
    }

    @Test
    @PactTestFor(pactMethod = "rejectUpdateOfNonDeferredCredential")
    void shouldRejectUpdateOfNonDeferredCredential(final MockServer mockServer) {
        assertClientError(() -> buildBusinessIssuer(mockServer).updateCredentialForDeferredFlowRequestCreation(
                MANAGEMENT_ID,
                Map.of("firstName", "John")), 400);
    }

    @Test
    @PactTestFor(pactMethod = "cancelCredential")
    void shouldCancelCredential(final MockServer mockServer) {
        final var response = buildBusinessIssuer(mockServer)
                .updateCredentialStatus(MANAGEMENT_ID, UpdateCredentialStatusRequestType.CANCELLED);

        assertThat(response.getStatus()).isEqualTo(CredentialStatusType.CANCELLED);
    }

    private static Map<String, Object> stateParameters() {
        return Map.of(
                "managementId", MANAGEMENT_ID.toString(),
                "offerId", OFFER_ID.toString());
    }

    private static void assertClientError(final Runnable request, final int expectedStatus) {
        assertThatThrownBy(request::run)
                .isInstanceOf(RestClientResponseException.class)
                .satisfies(exception -> assertThat(((RestClientResponseException) exception).getStatusCode().value())
                        .isEqualTo(expectedStatus));
    }
}
