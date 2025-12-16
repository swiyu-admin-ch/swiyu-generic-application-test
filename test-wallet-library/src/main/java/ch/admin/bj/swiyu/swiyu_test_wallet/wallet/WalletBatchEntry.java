package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.SdJwtSupport;
import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@Slf4j
@Getter
@Setter
public class WalletBatchEntry extends WalletEntry {

    private final List<KeyPair> holderKeyPairs = new ArrayList<>();
    private final List<ECKey> holderPublicKeys = new ArrayList<>();
    private final List<JwtProof> proofs = new ArrayList<>();
    private final List<String> issuedCredentials = new ArrayList<>();
    private final List<String> sdJwts = new ArrayList<>();
    private String currentNonce;

    public WalletBatchEntry(Wallet wallet) {
        super(wallet);
    }

    public String createPresentationForSdJwtIndex(final int index, RequestObject requestObject) {
        final String issuerSdJwt = issuedCredentials.get(index);
        final KeyPair keyPair = holderKeyPairs.get(index);
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
            throw new RuntimeException(e);
        }
    }

    private static String hashSdJwt(String credentialsSdJwt) {
        assertThat(credentialsSdJwt).isNotNull();

        try {
            MessageDigest digest = MessageDigest.getInstance("sha-256");
            byte[] hashBytes = digest.digest(credentialsSdJwt.getBytes());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public void generateHolderKeys() {
        final int count = getIssuerMetadata().getBatchSize();
        holderKeyPairs.clear();
        holderPublicKeys.clear();

        for (int i = 0; i < count; i++) {
            var pair = ECCryptoSupport.generateECKeyPair();
            var ec = new ECKey.Builder(Curve.P_256, (java.security.interfaces.ECPublicKey) pair.getPublic())
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID("holder-key-" + UUID.randomUUID())
                    .build();
            holderKeyPairs.add(pair);
            holderPublicKeys.add(ec);
        }
    }

    public String getIssuerDid(final int index) {
        final String vc = getIssuedCredentials().get(index);
        final JsonNode payload = SdJwtSupport.extractPayload(vc);
        return payload.get("iss").asText();
    }

    public void createProofs() {
        if (getCredentialOffer() == null || getToken() == null) {
            throw new IllegalStateException("Offer or token missing for proof generation");
        }

        proofs.clear();

        for (ECKey pub : holderPublicKeys) {
            String uniqueNonce = currentNonce != null ?
                    currentNonce + "-" + UUID.randomUUID().toString() :
                    getToken().getcNonce();

            var proof = new JwtProof(
                    getIssuerMetadata().getIssuerURI(),
                    uniqueNonce,
                    pub,
                    holderKeyPairs.get(holderPublicKeys.indexOf(pub))
            );
            proofs.add(proof);

            log.info("uniqueNonce " + uniqueNonce);
        }
    }

    public void createProofs(final String uniqueNonce) {
        if (getCredentialOffer() == null || getToken() == null) {
            throw new IllegalStateException("Offer or token missing for proof generation");
        }

        proofs.clear();

        for (ECKey pub : holderPublicKeys) {
            var proof = new JwtProof(
                    getIssuerMetadata().getIssuerURI(),
                    uniqueNonce,
                    pub,
                    holderKeyPairs.get(holderPublicKeys.indexOf(pub))
            );
            proofs.add(proof);

            log.info("uniqueNonce2 " + uniqueNonce);
        }
    }

    public List<String> getProofsAsJwt() {
        return proofs.stream().map(JwtProof::toJwt).toList();
    }

    public void setProofsFromJwt(List<JwtProof> proofs) {
        proofs.clear();
        for (JwtProof p : proofs) {
            proofs.add(p);
        }
    }

    private static class JwtProofWrapper extends JwtProof {
        private final String capturedJwt;

        JwtProofWrapper(String jwt) {
            super(null, null, null, null);
            this.capturedJwt = jwt;
        }

        @Override
        public String toJwt() {
            return capturedJwt;
        }
    }

    public void addIssuedCredential(String jwt) {
        issuedCredentials.add(jwt);
    }
}

