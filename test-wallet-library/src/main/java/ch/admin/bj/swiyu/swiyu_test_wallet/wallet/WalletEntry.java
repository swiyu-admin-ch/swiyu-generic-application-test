package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.gen.issuer.model.CredentialResponseEncryption;
import ch.admin.bj.swiyu.gen.issuer.model.IssuerCredentialRequestEncryption;
import ch.admin.bj.swiyu.gen.issuer.model.OAuthToken;
import ch.admin.bj.swiyu.gen.issuer.model.OpenIdConfiguration;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_response.CredentialResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.issuer_metadata.IssuerMetadata;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.SdJwtSupport;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.gson.JsonObject;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.net.URLDecoder;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
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
    private final Wallet wallet;
    private final KeyPair keyPair;
    private final ECKey proofPublicJwk;
    private URI issuerVCDeepLink;
    private CredentialOffer credentialOffer;
    private Map<String, Object> credentialConfigurationsSupported;
    private OpenIdConfiguration issuerWellKnownConfiguration;
    private OAuthToken token;
    private IssuerMetadata issuerMetadata;
    private JsonObject credentialConfigurationSupported;
    private String issuerSdJwt;
    private RSAKey encrypterJwk;
    private JsonNode vctDetails;
    private UUID transactionId;
    private ECKey ephemeralEncryptionKey;
    private CredentialResponse credentialResponse;

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
        credentialConfigurationSupported = issuerMetadata.getCredentialConfigurationById(credentialOffer.getCredentialConfiguraionId());
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

    public String createPresentationForSdJwt(String issuerSdJwt, RequestObject requestObject) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("kb+jwt"))
                    .build();

            String sdJwtHash = hashSdJwt(issuerSdJwt);
            String audience = requestObject.getClientId();
            String nonce = requestObject.getNonce();

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .claim("sd_hash", sdJwtHash)
                    .audience(audience)
                    .claim("nonce", nonce)
                    .issueTime(new Date())
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            signedJWT.sign(ECCryptoSupport.createECDSASigner(keyPair.getPrivate()));

            String serializedJwt = signedJWT.serialize();
            return issuerSdJwt + serializedJwt;
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public JwtProof createProof() {
        if (credentialOffer == null) {
            throw new IllegalStateException(CREDENTIAL_OFFER_NOT_SET);
        }
        if (token == null) {
            throw new IllegalStateException("token not set.");
        }
        if (getIssuerMetadata() == null) {
            throw new IllegalStateException(ISSUER_METADATA_NOT_SET);
        }

        String cNonce = token.getcNonce();
        String audience = getIssuerMetadata().getIssuerURI();
        return new JwtProof(audience, cNonce, proofPublicJwk, keyPair);
    }

    private static String hashSdJwt(String credentialsSdJwt) {
        assertThat(credentialsSdJwt).isNotNull();

        try {
            MessageDigest digest = MessageDigest.getInstance("sha-256");
            byte[] hashBytes = digest.digest(credentialsSdJwt.getBytes());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public boolean isEncryptionEnabled() {
        final IssuerCredentialRequestEncryption req = issuerMetadata.getCredentialRequestEncryption();

        return (req != null && req.getEncryptionRequired()) || wallet.isUseEncryption();
    }

    public RestClient getRestClient() {
        if (wallet == null) {
            throw new IllegalStateException("wallet not set.");
        }

        return wallet.getRestClient();
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

    public String getIssuerDid() {
        var vc = getVerifiableCredential();
        var payload = SdJwtSupport.extractPayload(vc);
        return payload.get("iss").asText();
    }

    public URI getIssuerCredentialUri() {
        if (issuerMetadata == null) {
            throw new IllegalStateException(ISSUER_METADATA_NOT_SET);
        }

        return issuerMetadata.getCredentialEndpointURI();
    }

    public URI getIssuerDeferredCredentialUri() {
        if (issuerMetadata == null) {
            throw new IllegalStateException(ISSUER_METADATA_NOT_SET);
        }

        return issuerMetadata.getDeferredCredentialEndpointURI();
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

    public URI getVctUri() {
        var vct = getVct();
        try {
            return toUri(vct);
        } catch (RuntimeException e) {
            var issuerURI = getIssuerMetadata().getIssuerURI();
            return toUri(issuerURI + "/oid4vci/vct/" + vct);
        }
    }

    public String getVct() {
        var vc = getVerifiableCredential();
        var payload = SdJwtSupport.extractPayload(vc);
        return payload.get("vct").asText();
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

    public CredentialResponseEncryption createCredentialResponseEncryption() {
        if (issuerMetadata == null) {
            throw new IllegalStateException(ISSUER_METADATA_NOT_SET);
        }

        if (ephemeralEncryptionKey == null) {
            generateEphemeralEncryptionKey();
        }

        var encryptionMetadata = issuerMetadata.getCredentialResponseEncryption();

        var responseEncryption = new CredentialResponseEncryption();
        responseEncryption.setAlg(encryptionMetadata.getAlgValuesSupported().getFirst());
        responseEncryption.setEnc(encryptionMetadata.getEncValuesSupported().getFirst());
        responseEncryption.setJwk(ephemeralEncryptionKey.toPublicJWK().toJSONObject());

        return responseEncryption;
    }

}
