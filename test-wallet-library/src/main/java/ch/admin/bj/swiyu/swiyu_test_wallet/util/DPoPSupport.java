package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.collections.list.CursorableLinkedList;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.UUID;

public class DPoPSupport {

    final static String MESSAGE_DIGEST_ALGORITHM = "SHA-256";

    public static String tokenToAth(final String token) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(String.format("%s algorithm not found", MESSAGE_DIGEST_ALGORITHM), e);
        }
        final byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));

        return Base64.encode(hash).toString();
    }

    public static String createDpopProofForToken(
            String uri,
            String nonce,
            KeyPair dpopKeyPair,
            ECKey dpopPublicJwk,
            String token
    )  {
        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(dpopPublicJwk)
                .build();

        final Date now = new Date();
        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("htm", "POST")
                .claim("htu", uri)
                .claim("nonce", nonce)
                .claim("ath", tokenToAth(token))
                .issueTime(now)
                .build();

        try {
            final SignedJWT jwt = new SignedJWT(header, claimsSet);
            jwt.sign(ECCryptoSupport.createECDSASigner(dpopKeyPair.getPrivate()));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to create DPoP proof", e);
        }
    }





    public static String createDpopProofForToken(
            String uri,
            String nonce,
            KeyPair dpopKeyPair,
            ECKey dpopPublicJwk
    ) {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(dpopPublicJwk)
                .build();

        Date now = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("htm", "POST")
                .claim("htu", uri)
                .claim("nonce", nonce)
                .issueTime(now)
                .build();

        try {
            SignedJWT jwt = new SignedJWT(header, claimsSet);
            jwt.sign(ECCryptoSupport.createECDSASigner(dpopKeyPair.getPrivate()));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to create DPoP proof", e);
        }
    }
}
