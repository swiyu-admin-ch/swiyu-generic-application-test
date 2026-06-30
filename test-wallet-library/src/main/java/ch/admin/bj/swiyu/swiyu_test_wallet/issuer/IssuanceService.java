package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import ch.admin.bj.swiyu.gen.issuer.invoker.ApiClient;
import ch.admin.bj.swiyu.gen.issuer.model.IssuerMetadata;
import ch.admin.bj.swiyu.gen.issuer.model.OAuthAuthorizationServerMetadata;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JsonConverter;

import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

public class IssuanceService {

    private final ch.admin.bj.swiyu.gen.issuer.api.WellKnownEndpointsApiApi wellKnownApi;

    public IssuanceService(String issuerUrl) {
        RestClient restClient = RestClient.builder().build();
        var apiClient = new ApiClient(restClient).setBasePath(issuerUrl);

        wellKnownApi = new ch.admin.bj.swiyu.gen.issuer.api.WellKnownEndpointsApiApi(apiClient);
    }

    public IssuerMetadata getWellKnownCredentialIssuerInfo() {
        return JsonConverter.objectMapper().convertValue(
                wellKnownApi.getIssuerMetadata(MediaType.APPLICATION_JSON_VALUE),
                IssuerMetadata.class);
    }

    public OAuthAuthorizationServerMetadata getWellKnownOpenIdConfiguration() {
        return wellKnownApi.getAuthorizationServerMetadata();
    }

    public OAuthAuthorizationServerMetadata getWellKnownOAuthAuthorizationServer() {
        return wellKnownApi.getAuthorizationServerMetadata();
    }
}
