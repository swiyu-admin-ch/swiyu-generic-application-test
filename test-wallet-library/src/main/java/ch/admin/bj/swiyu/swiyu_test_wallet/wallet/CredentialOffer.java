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
        return getPreAuthorizedCodeGrant().get("pre-authorized_code").getAsString();
    }

    /**
     * Returns the transaction-code metadata advertised for the pre-authorized code grant.
     *
     * @return the metadata object, or {@code null} when the offer does not require a transaction code
     */
    public JsonObject getTransactionCodeMetadata() {
        return getPreAuthorizedCodeGrant().getAsJsonObject("tx_code");
    }

    private JsonObject getPreAuthorizedCodeGrant() {
        var grants = credentialOfferJson.getAsJsonObject("grants");
        return grants.getAsJsonObject("urn:ietf:params:oauth:grant-type:pre-authorized_code");
    }
}
