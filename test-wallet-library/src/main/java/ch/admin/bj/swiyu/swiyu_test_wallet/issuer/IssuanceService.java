package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import ch.admin.bj.swiyu.gen.issuer.invoker.ApiClient;
import ch.admin.bj.swiyu.gen.issuer.model.IssuerMetadata;
import ch.admin.bj.swiyu.gen.issuer.model.OpenIdConfiguration;
import org.springframework.web.client.RestClient;

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
        return wellKnownApi.getIssuerMetadata();
    }

    public OpenIdConfiguration getWellKnownOpenIdConfiguration() {
        return wellKnownApi.getOpenIDConfiguration();
    }

    public OpenIdConfiguration getWellKnownOAuthAuthorizationServer() {
        return wellKnownApi.getOpenIDConfiguration();
    }
}
