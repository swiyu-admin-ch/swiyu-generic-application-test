package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.KeyPair;
import java.util.Date;
import java.util.UUID;

public class DPoPSupport {

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
