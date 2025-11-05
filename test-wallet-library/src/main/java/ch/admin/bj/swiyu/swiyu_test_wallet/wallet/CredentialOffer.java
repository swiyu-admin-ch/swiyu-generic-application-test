package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URI;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;


public class CredentialOffer {
    private final JsonObject credentialOfferJson;

    public CredentialOffer(String credentialOfferContent) {
        this.credentialOfferJson = JsonParser.parseString(credentialOfferContent).getAsJsonObject();
    }

    public String getCredentialIssuerUriAsString() {
        return credentialOfferJson.get("credential_issuer").getAsString();
    }

    public String getCredentialConfiguraionId() {
        var configs = credentialOfferJson.get("credential_configuration_ids").getAsJsonArray();
        return configs.get(0).getAsString();
    }

    public URI getCredentialIssuerUri() {
        var credentialIssuerUri = getCredentialIssuerUriAsString();
        return toUri(credentialIssuerUri);
    }

    public String getCredentialBaseIssuerUriAsString() {
        final URI url = this.getCredentialIssuerUri();
        return String.format("%s://%s", url.getScheme(), url.getHost());
    }

    public String getPreAuthorizedCode() {
        var grants = credentialOfferJson.get("grants").getAsJsonObject();
        var preAuthorizedCode = grants.get("urn:ietf:params:oauth:grant-type:pre-authorized_code").getAsJsonObject();
        return preAuthorizedCode.get("pre-authorized_code").getAsString();
    }
}
