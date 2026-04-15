package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import ch.admin.bj.swiyu.jwtutil.JwtUtil;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;

import java.security.PrivateKey;
import java.util.Date;
import java.util.List;

public class AttestationFactory {

    private static final JOSEObjectType ATTESTATION_TYP = new JOSEObjectType("key-attestation+jwt");

    public static String validHighAttestation(final ECKey attestedKey, final String issuerDid, final PrivateKey signingKey, final String kid) {
        return buildAttestation(attestedKey, issuerDid, signingKey, kid, "iso_18045_high");
    }

    public static String validBasicAttestation(final ECKey attestedKey, final String issuerDid, final PrivateKey signingKey, final String kid) {
        return buildAttestation(attestedKey, issuerDid, signingKey, kid, "iso_18045_enhanced_basic");
    }

    public static String invalidAttestation() {
        return "invalid.jwt.token";
    }

    private static String buildAttestation(final ECKey attestedKey, final String issuerDid, final PrivateKey signingKey, final String kid, final String level) {
        return JwtUtil.signJwt(
                new JWTClaimsSet.Builder()
                        .issuer(issuerDid)
                        .issueTime(new Date())
                        .expirationTime(new Date(System.currentTimeMillis() + 60000))
                        .claim("key_storage", List.of(level))
                        .claim("attested_keys", List.of(attestedKey.toPublicJWK().toJSONObject()))
                        .build(),
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(ATTESTATION_TYP)
                        .keyID(kid)
                        .build(),
                ECCryptoSupport.createECDSASigner(signingKey)
        ).serialize();
    }
}