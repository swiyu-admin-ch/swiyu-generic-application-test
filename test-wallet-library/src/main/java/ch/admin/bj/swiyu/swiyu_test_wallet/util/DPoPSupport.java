package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

public class DPoPSupport {

    static final String MESSAGE_DIGEST_ALGORITHM = "SHA-256";

    private DPoPSupport() {
        throw new AssertionError("Utility class should not be instantiated");
    }

    public static String tokenToAth(final String token) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(String.format("%s algorithm not found", MESSAGE_DIGEST_ALGORITHM), e);
        }
        final byte[] hash = digest.digest(token.getBytes(StandardCharsets.US_ASCII));

        return Base64.getUrlEncoder().encodeToString(hash);
    }

    public static String createDpopProofForToken(
            String uri,
            String nonce,
            KeyPair dpopKeyPair,
            ECKey dpopPublicJwk
    ) {
        return createDpopProofForToken(
                uri,
                nonce,
                dpopKeyPair,
                dpopPublicJwk,
                null
        );
    }

    public static String createDpopProofForToken(
            String uri,
            String nonce,
            KeyPair dpopKeyPair,
            ECKey dpopPublicJwk,
            String token
    ) {
        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(dpopPublicJwk)
                .build();

        final JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("htm", "POST")
                .claim("htu", uri)
                .claim("nonce", nonce)
                .issueTime(new Date());

        if (token != null) {
            claimsBuilder.claim("ath", tokenToAth(token));
        }

        try {
            final SignedJWT jwt = new SignedJWT(header, claimsBuilder.build());
            jwt.sign(ECCryptoSupport.createECDSASigner(dpopKeyPair.getPrivate()));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to create DPoP proof", e);
        }
    }
}
