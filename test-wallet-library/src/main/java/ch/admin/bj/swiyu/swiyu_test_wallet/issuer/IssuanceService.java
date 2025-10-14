package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import ch.admin.bj.swiyu.gen.issuer.invoker.ApiClient;
import ch.admin.bj.swiyu.gen.issuer.model.OpenIdConfiguration;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.springframework.web.client.RestClient;

import java.util.Map;

public class IssuanceService {

    private final ch.admin.bj.swiyu.gen.issuer.api.WellKnownEndpointsApiApi wellKnownApi;
    private final ch.admin.bj.swiyu.gen.issuer.api.IssuerOid4VciApiApi issuerOid4VciApiApi;

    public IssuanceService(String issuerUrl) {
        RestClient restClient = RestClient.builder().build();
        var apiClient = new ApiClient(restClient).setBasePath(issuerUrl);

        wellKnownApi = new ch.admin.bj.swiyu.gen.issuer.api.WellKnownEndpointsApiApi(apiClient);
        issuerOid4VciApiApi = new ch.admin.bj.swiyu.gen.issuer.api.IssuerOid4VciApiApi(apiClient);
    }

    public IssuerMetadata getWellKnownCredentialIssuerInfo() {
        Map<String, Object> rawMetadata = wellKnownApi.getIssuerMetadata();

        JsonObject rawMetadataJson = new Gson().toJsonTree(rawMetadata).getAsJsonObject();

        return new IssuerMetadata(rawMetadataJson);
    }

    public OpenIdConfiguration getWellKnownOpenIdConfiguration() {
        return wellKnownApi.getOpenIDConfiguration();
    }

    public OpenIdConfiguration getWellKnownOAuthAuthorizationServer() {
        return wellKnownApi.getOpenIDConfiguration();
    }
}
