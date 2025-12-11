package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import ch.admin.bj.swiyu.gen.issuer.model.IssuerCredentialRequestEncryption;
import ch.admin.bj.swiyu.gen.issuer.model.IssuerCredentialResponseEncryption;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import lombok.Getter;
import lombok.ToString;

import java.net.URI;
import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

@Getter
@ToString
public class IssuerMetadata {

    private static final ObjectMapper MAPPER = new ObjectMapper();
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

    public IssuerCredentialResponseEncryption getCredentialResponseEncryption() {
        return parseEncryptionObject("credential_response_encryption", IssuerCredentialResponseEncryption.class);
    }

    public IssuerCredentialRequestEncryption getCredentialRequestEncryption() {
        return parseEncryptionObject("credential_request_encryption", IssuerCredentialRequestEncryption.class);
    }

    private <T> T parseEncryptionObject(String key, Class<T> clazz) {
        if (!data.has(key) || !data.get(key).isJsonObject()) {
            return null;
        }
        try {
            Map<String, Object> map = MAPPER.readValue(
                    data.getAsJsonObject(key).toString(),
                    new TypeReference<>() {
                    }
            );
            return MAPPER.convertValue(map, clazz);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse " + key + " as " + clazz.getSimpleName(), e);
        }
    }

    public int getBatchSize() {
        JsonObject batch = data.getAsJsonObject("batch_credential_issuance");
        return batch != null && batch.has("batch_size")
                ? batch.get("batch_size").getAsInt()
                : 1;
    }


}
