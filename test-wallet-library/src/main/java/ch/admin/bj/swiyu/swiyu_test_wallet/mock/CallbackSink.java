package ch.admin.bj.swiyu.swiyu_test_wallet.mock;

import ch.admin.bj.swiyu.gen.issuer.model.WebhookCallback;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.MediaType;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

/**
 * Where the Credential Issuer and the Verifier send their webhook callbacks. Each has its own path so a callback of one is
 * never counted as a callback of the other. Issuer callbacks are also parsed and kept; Verifier callbacks are only
 * recorded by MockServer (the tests count them).
 */
final class CallbackSink {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .disable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    private final List<WebhookCallback> receivedIssuerCallbacks = new CopyOnWriteArrayList<>();

    List<WebhookCallback> issuerCallbacks() {
        return receivedIssuerCallbacks;
    }

    void clearIssuerCallbacks() {
        receivedIssuerCallbacks.clear();
    }

    void registerRoutes(final MockServerClient mockServerClient) {
        mockServerClient.when(request().withMethod("POST").withPath(MockServices.ISSUER_CALLBACK_PATH))
                .respond(httpRequest -> {
                    final WebhookCallback callback = OBJECT_MAPPER.readValue(
                            httpRequest.getBodyAsString(),
                            WebhookCallback.class
                    );
                    receivedIssuerCallbacks.add(callback);
                    return response()
                            .withStatusCode(204)
                            .withContentType(MediaType.APPLICATION_JSON);
                });

        mockServerClient.when(request().withMethod("POST").withPath(MockServices.VERIFIER_CALLBACK_PATH))
                .respond(response().withStatusCode(204).withContentType(MediaType.APPLICATION_JSON));
    }
}
