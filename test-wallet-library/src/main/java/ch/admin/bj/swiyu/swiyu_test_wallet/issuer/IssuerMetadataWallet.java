package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import ch.admin.bj.swiyu.gen.issuer.model.CredentialConfiguration;
import ch.admin.bj.swiyu.gen.issuer.model.IssuerMetadata;
import lombok.Getter;
import lombok.ToString;

import java.net.URI;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

@Getter
@ToString
public class IssuerMetadataWallet extends IssuerMetadata {


    public String getIssuerURI() {
        return getCredentialIssuer();
    }

    public URI getCredentialEndpointURI() {
        return toUri(getCredentialEndpoint());
    }

    public URI getDeferredCredentialEndpointURI() {
        return toUri(getDeferredCredentialEndpoint());
    }

    public CredentialConfiguration getCredentialConfigurationById(String supportedId) {
        var credentialConfigurationsSupported = this.getCredentialConfigurationsSupported();
        return credentialConfigurationsSupported.get(supportedId);
    }

    public URI getNonceEndpointURI() {
        return toUri(getNonceEndpoint());
    }
}
