package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import ch.admin.bj.swiyu.gen.issuer.invoker.ApiClient;
import ch.admin.bj.swiyu.gen.issuer.model.IssuerMetadata;
import ch.admin.bj.swiyu.gen.issuer.model.OAuthAuthorizationServerMetadata;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.springframework.web.client.RestClient;

public class IssuanceService {

    private final ch.admin.bj.swiyu.gen.issuer.api.WellKnownEndpointsApiApi wellKnownApi;

    public IssuanceService(String issuerUrl) {
        RestClient restClient = RestClient.builder().build();
        var apiClient = new ApiClient(restClient).setBasePath(issuerUrl);

        wellKnownApi = new ch.admin.bj.swiyu.gen.issuer.api.WellKnownEndpointsApiApi(apiClient);
    }

    public ch.admin.bj.swiyu.swiyu_test_wallet.test_support.issuer_metadata.IssuerMetadata getWellKnownCredentialIssuerInfo() {
        // @TODO Remove the custom IssuerMetadata class
        return new ch.admin.bj.swiyu.swiyu_test_wallet.test_support.issuer_metadata.IssuerMetadata(wellKnownApi.getIssuerMetadata());
    }

    public OAuthAuthorizationServerMetadata getWellKnownOpenIdConfiguration() {
        return wellKnownApi.getAuthorizationServerMetadata();
    }

    public OAuthAuthorizationServerMetadata getWellKnownOAuthAuthorizationServer() {
        return wellKnownApi.getAuthorizationServerMetadata();
    }
}
