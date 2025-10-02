package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import lombok.Getter;
import lombok.ToString;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

@Getter
@ToString
public class IssuerMetadata {

    private final JsonObject data;

    public IssuerMetadata(JsonObject rawMetadata) {
        this.data = rawMetadata;
    }

    public String getIssuerURI() {
        if (data.get("credential_issuer") == null) {
            return null;
        }

        return data.get("credential_issuer").getAsString();
    }

    public URI getCredentialEndpointURI() {
        var credentialEndpointValue = data.get("credential_endpoint").getAsString();
        return toUri(credentialEndpointValue);
    }

    public URI getDeferredCredentialEndpointURI() {
        var credentialEndpointValue = data.get("deferred_credential_endpoint").getAsString();
        return toUri(credentialEndpointValue);
    }

    public JsonArray getDisplay() {
        return data.get("display").getAsJsonArray();
    }

    public JsonObject getSupportedCredentialConfigurations() {
        if (data.get("credential_configurations_supported") == null) {
            return null;
        }
        return data.get("credential_configurations_supported").getAsJsonObject();
    }

    public JsonObject getCredentialConfigurationById(String supportedId) {
        var credentialConfigurationsSupported = getSupportedCredentialConfigurations();
        return credentialConfigurationsSupported.get(supportedId).getAsJsonObject();
    }

    public URI getNonceEndpointURI() {
        if (data.get("nonce_endpoint") == null) {
            return null;
        }

        return toUri(data.get("nonce_endpoint").getAsString());
    }
}
