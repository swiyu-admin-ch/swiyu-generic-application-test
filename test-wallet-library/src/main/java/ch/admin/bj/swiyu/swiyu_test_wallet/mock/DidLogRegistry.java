package ch.admin.bj.swiyu.swiyu_test_wallet.mock;

import org.mockserver.client.MockServerClient;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;

/**
 * The Base Registry: serves the {@code did.jsonl} log of every registered DID at {@code /api/v1/did/<id>/did.jsonl}
 * (Swiss profile anchor, did:webvh).
 */
final class DidLogRegistry {

    private final Map<String, String> didLogsById = new ConcurrentHashMap<>();

    void register(final String did, final String didLog) {
        didLogsById.put(extractDidId(did), didLog);
    }

    void registerRoutes(final MockServerClient mockServerClient) {
        mockServerClient
                .when(request()
                        .withMethod("GET")
                        .withPath("/api/v1/did/.*/did.jsonl"))
                .respond(httpRequest -> {

                    String requestedDidId = extractDidIdFromPath(httpRequest.getPath().getValue());
                    final String didLog = didLogsById.get(requestedDidId);

                    if (didLog != null) {
                        return response()
                                .withStatusCode(200)
                                .withHeader(CONTENT_TYPE, "application/jsonl+json")
                                .withBody(didLog);
                    }

                    return response().withStatusCode(404);
                });
    }

    private static String extractDidIdFromPath(final String path) {
        String normalized = path.endsWith("/did.jsonl") ? path.substring(0, path.length() - "/did.jsonl".length()) : path;
        return normalized.substring(normalized.lastIndexOf("/") + 1);
    }

    private static String extractDidId(final String did) {
        return did.substring(did.lastIndexOf(":") + 1);
    }
}
