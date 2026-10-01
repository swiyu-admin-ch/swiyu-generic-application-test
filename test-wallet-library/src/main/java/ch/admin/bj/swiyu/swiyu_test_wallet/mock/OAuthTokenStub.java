package ch.admin.bj.swiyu.swiyu_test_wallet.mock;

import org.mockserver.client.MockServerClient;
import org.mockserver.model.MediaType;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

/** The OAuth token endpoint of the services the Credential Issuer and Verifier call: always answers with the same tokens. */
final class OAuthTokenStub {

    void registerRoutes(final MockServerClient mockServerClient) {
        mockServerClient.when(request().withMethod("POST").withPath("/openid-connect/token"))
                .respond(response().withStatusCode(200).withContentType(MediaType.APPLICATION_JSON)
                        .withBody("{\"access_token\": \"access_token\", \"refresh_token\": \"refresh_token\"}"));
    }
}
