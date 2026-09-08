package ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.LambdaDsl;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit5.PactConsumerTest;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.V4Pact;
import au.com.dius.pact.core.model.annotations.Pact;
import ch.admin.bj.swiyu.gen.issuer.model.StatusListUpdate;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.CONSUMER;
import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.JSON_CONTENT_TYPE_REGEX;
import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.PROVIDER;
import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.STATUS_LIST_ID;
import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.STATUS_REGISTRY_URL;
import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.URL_REGEX;
import static ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact.IssuerManagementConsumerPactSupport.buildBusinessIssuer;
import static org.assertj.core.api.Assertions.assertThat;

@PactConsumerTest
@PactTestFor(providerName = PROVIDER, pactVersion = PactSpecVersion.V4)
class StatusListManagementConsumerPactTest {

    private static final String STATUS_LIST_PATH = "/management/api/status-list/" + STATUS_LIST_ID;
    private static final String DYNAMIC_STATUS_LIST_PATH = "/management/api/status-list/${statusListId}";

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact createStatusList(final PactDslWithProvider builder) {
        return builder
                .given("status list creation is available", Map.of(
                        "statusListId", STATUS_LIST_ID.toString(),
                        "statusRegistryUrl", STATUS_REGISTRY_URL))
                .uponReceiving("IF-113 POST creates a status list")
                .method("POST")
                .path("/management/api/status-list")
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(LambdaDsl.newJsonBody(body -> body
                        .nullValue("type")
                        .numberValue("maxLength", 1000)
                        .object("config", config -> config
                                .nullValue("purpose")
                                .numberValue("bits", 2))
                        .nullValue("configuration_override")).build())
                .willRespondWith()
                .status(200)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(statusListResponseBody())
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact getStatusList(final PactDslWithProvider builder) {
        return builder
                .given("a status list exists", Map.of(
                        "statusListId", STATUS_LIST_ID.toString(),
                        "statusRegistryUrl", STATUS_REGISTRY_URL))
                .uponReceiving("IF-113 GET retrieves a status list")
                .method("GET")
                .pathFromProviderState(DYNAMIC_STATUS_LIST_PATH, STATUS_LIST_PATH)
                .willRespondWith()
                .status(200)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(statusListResponseBody())
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    V4Pact publishStatusList(final PactDslWithProvider builder) {
        return builder
                .given("a status list exists and can be published", Map.of(
                        "statusListId", STATUS_LIST_ID.toString(),
                        "statusRegistryUrl", STATUS_REGISTRY_URL))
                .uponReceiving("IF-113 POST publishes a status list")
                .method("POST")
                .pathFromProviderState(DYNAMIC_STATUS_LIST_PATH, STATUS_LIST_PATH)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(LambdaDsl.newJsonBody(body -> body.nullValue("configuration_override")).build())
                .willRespondWith()
                .status(200)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(statusListResponseBody())
                .toPact(V4Pact.class);
    }

    @Test
    @PactTestFor(pactMethod = "createStatusList")
    void shouldCreateStatusList(final MockServer mockServer) {
        final var response = buildBusinessIssuer(mockServer).createStatusList(1000, 2);

        assertThat(response.getId()).isEqualTo(STATUS_LIST_ID);
        assertThat(response.getStatusRegistryUrl()).isEqualTo(STATUS_REGISTRY_URL);
    }

    @Test
    @PactTestFor(pactMethod = "getStatusList")
    void shouldRetrieveStatusList(final MockServer mockServer) {
        final var response = buildBusinessIssuer(mockServer).getStatusListById(STATUS_LIST_ID);

        assertThat(response.getId()).isEqualTo(STATUS_LIST_ID);
        assertThat(response.getRemainingListEntries()).isEqualTo(1000);
    }

    @Test
    @PactTestFor(pactMethod = "publishStatusList")
    void shouldPublishStatusList(final MockServer mockServer) {
        final var response = buildBusinessIssuer(mockServer)
                .updateStatusListRegistryEntry(STATUS_LIST_ID, new StatusListUpdate());

        assertThat(response.getId()).isEqualTo(STATUS_LIST_ID);
        assertThat(response.getStatusRegistryUrl()).isEqualTo(STATUS_REGISTRY_URL);
    }

    private static au.com.dius.pact.consumer.dsl.DslPart statusListResponseBody() {
        return LambdaDsl.newJsonBody(body -> body
                .uuid("id", STATUS_LIST_ID)
                .stringMatcher("statusRegistryUrl", URL_REGEX, STATUS_REGISTRY_URL)
                .integerType("maxListEntries", 1000)
                .integerType("remainingListEntries", 1000)
                .object("config", config -> config.integerType("bits", 2))).build();
    }
}
