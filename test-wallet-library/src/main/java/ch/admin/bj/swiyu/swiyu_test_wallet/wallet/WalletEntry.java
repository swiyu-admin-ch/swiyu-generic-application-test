package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.gen.issuer.model.IssuerMetadata;
import ch.admin.bj.swiyu.gen.issuer.model.OAuthAuthorizationServerMetadata;
import ch.admin.bj.swiyu.gen.issuer.model.OAuthToken;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_response.CredentialResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import com.google.gson.JsonObject;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.URLDecoder;
import java.security.KeyPair;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@Getter
@Setter
@Slf4j
public class WalletEntry {
    public static final String CREDENTIAL_OFFER_KEY_AND_EQUAL = "credential_offer=";
    public static final String ISSUER_METADATA_NOT_SET = "issuer metadata is not set.";
    public static final String CREDENTIAL_OFFER_NOT_SET = "credential offer not set.";
    protected final Wallet wallet;
    private final KeyPair keyPair;
    private final ECKey proofPublicJwk;
    private URI issuerVCDeepLink;
    private CredentialOffer credentialOffer;
    private Map<String, Object> credentialConfigurationsSupported;
    private OAuthAuthorizationServerMetadata issuerWellKnownConfiguration;
    private JsonNode issuerWellKnownConfigurationRaw;
    private OAuthToken token;
    private IssuerMetadata issuerMetadata;
    private JsonNode issuerMetadataRaw;
    private JsonObject credentialConfigurationSupported;
    private String issuerSdJwt;
    private RSAKey encrypterJwk;
    private JsonNode vctDetails;
    private UUID transactionId;
    private ECKey ephemeralEncryptionKey;
    private CredentialResponse credentialResponse;
    private String cNonce;
    private String transactionCode;

    public WalletEntry(final Wallet wallet) {
        this.wallet = wallet;
        keyPair = ECCryptoSupport.generateECKeyPair();
        proofPublicJwk = new ECKey.Builder(Curve.P_256, (java.security.interfaces.ECPublicKey) keyPair.getPublic())
                .keyID("key-a")
                .build();
    }

    public void setCredentialConfigurationSupported() {
        if (issuerMetadata == null) {
            throw new IllegalStateException(ISSUER_METADATA_NOT_SET);
        }
        var config = issuerMetadata.getCredentialConfigurationsSupported()
                .get(credentialOffer.getCredentialConfiguraionId());

        try {
            ObjectMapper mapper = new ObjectMapper();
            var jsonString = mapper.writeValueAsString(config);
            credentialConfigurationSupported = com.google.gson.JsonParser.parseString(jsonString).getAsJsonObject();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to convert credential configuration to JsonObject", e);
        }
    }

    public void receiveDeepLinkAndValidateIt(URI deepLink) {
        if (this.issuerVCDeepLink != null)
            throw new IllegalStateException("wallet entry already used.");

        this.issuerVCDeepLink = deepLink;

        var decoded = URLDecoder.decode(issuerVCDeepLink.getQuery(), java.nio.charset.StandardCharsets.UTF_8);
        assertThat(decoded).startsWith(CREDENTIAL_OFFER_KEY_AND_EQUAL);

        String credentialOfferContent = decoded.substring(CREDENTIAL_OFFER_KEY_AND_EQUAL.length());

        credentialOffer = new CredentialOffer(credentialOfferContent);
        assertThat(credentialOffer.getCredentialIssuerUriAsString()).isNotNull();
        assertThat(credentialOffer.getPreAuthorizedCode()).isNotNull();
    }
    public URI getIssuerTokenUri() {
        if (issuerWellKnownConfiguration == null) {
            throw new IllegalStateException("issuer well known configuration not set.");
        }

        return toUri(issuerWellKnownConfiguration.getTokenEndpoint());
    }

    public String getPreAuthorizedCode() {
        if (credentialOffer == null) {
            throw new IllegalStateException(CREDENTIAL_OFFER_NOT_SET);
        }

        return credentialOffer.getPreAuthorizedCode();
    }

    public URI getIssuerUri() {
        if (credentialOffer == null) {
            throw new IllegalStateException(CREDENTIAL_OFFER_NOT_SET);
        }

        return credentialOffer.getCredentialIssuerUri();
    }
    public URI getIssuerCredentialUri() {
        if (issuerMetadata == null) {
            throw new IllegalStateException(ISSUER_METADATA_NOT_SET);
        }

        return toUri(issuerMetadata.getCredentialEndpoint());
    }

    public URI getIssuerDeferredCredentialUri() {
        if (issuerMetadata == null) {
            throw new IllegalStateException(ISSUER_METADATA_NOT_SET);
        }

        return toUri(issuerMetadata.getDeferredCredentialEndpoint());
    }

    public OAuthToken getToken() {
        if (token == null) {
            throw new IllegalStateException("token not set.");
        }

        return token;
    }

    public String getVerifiableCredential() {
        if (issuerSdJwt == null) {
            throw new IllegalStateException("verifiable credential not set.");
        }

        return issuerSdJwt;
    }
    public void generateEphemeralEncryptionKey() {
        try {
            final ECKey key = new ECKeyGenerator(Curve.P_256)
                    .algorithm(JWEAlgorithm.ECDH_ES)
                    .keyUse(KeyUse.ENCRYPTION)
                    .generate();
            this.setEphemeralEncryptionKey(key);
        } catch (Exception e) {
            throw new IllegalStateException("Error during ephemeral encryption key", e);
        }
    }
}
