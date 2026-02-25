package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.issuer_metadata;

import ch.admin.bj.swiyu.gen.issuer.model.*;
import com.google.gson.JsonObject;
import lombok.Getter;
import lombok.ToString;

import java.net.URI;
import java.util.List;
import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

@Getter
@ToString
public class IssuerMetadata {

    private final ch.admin.bj.swiyu.gen.issuer.model.IssuerMetadata data;

    public IssuerMetadata(ch.admin.bj.swiyu.gen.issuer.model.IssuerMetadata rawMetadata) {
        if (rawMetadata == null) {
            throw new IllegalArgumentException("IssuerMetadata must not be null");
        }
        this.data = rawMetadata;
    }

    public String getIssuerURI() {
        return data.getCredentialIssuer();
    }

    public URI getCredentialEndpointURI() {
        return data.getCredentialEndpoint() == null
                ? null
                : toUri(data.getCredentialEndpoint());
    }

    public URI getDeferredCredentialEndpointURI() {
        return data.getDeferredCredentialEndpoint() == null
                ? null
                : toUri(data.getDeferredCredentialEndpoint());
    }

    public URI getNonceEndpointURI() {
        return data.getNonceEndpoint() == null
                ? null
                : toUri(data.getNonceEndpoint());
    }

    public List<MetadataIssuerDisplayInfo> getDisplay() {
        return data.getDisplay();
    }

    public Map<String, CredentialConfiguration> getSupportedCredentialConfigurations() {
        return data.getCredentialConfigurationsSupported();
    }

    public CredentialConfiguration getCredentialConfigurationById(String supportedId) {
        if (data.getCredentialConfigurationsSupported() == null) {
            return null;
        }
        return data.getCredentialConfigurationsSupported().get(supportedId);
    }

    public IssuerCredentialResponseEncryption getCredentialResponseEncryption() {
        return data.getCredentialResponseEncryption();
    }

    public IssuerCredentialRequestEncryption getCredentialRequestEncryption() {
        return data.getCredentialRequestEncryption();
    }

    public int getBatchSize() {
        if (data.getBatchCredentialIssuance() == null) {
            return 1;
        }
        Integer size = data.getBatchCredentialIssuance().getBatchSize();
        return size == null ? 1 : size;
    }
}