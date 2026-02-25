package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import ch.admin.bj.swiyu.dpop.DpopConstants;
import ch.admin.bj.swiyu.dpop.DpopHashUtil;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.experimental.UtilityClass;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@UtilityClass
public class DPoPSupport {

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
        final JWSAlgorithm algorithm = JWSAlgorithm.parse(
                DpopConstants.SUPPORTED_ALGORITHMS.get(0)
        );

        final JWSHeader header = new JWSHeader.Builder(algorithm)
                .type(new JOSEObjectType(DpopConstants.DPOP_JWT_HEADER_TYP))
                .jwk(dpopPublicJwk)
                .build();

        final JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("htm", "POST")
                .claim("htu", uri)
                .claim("nonce", nonce)
                .issueTime(new Date());

        if (token != null) {
            claimsBuilder.claim("ath", DpopHashUtil.sha256(token));
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
