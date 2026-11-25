package ch.admin.bj.swiyu.swiyu_test_wallet.fixture;

import ch.admin.bj.swiyu.swiyu_test_wallet.identity.KeyUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.experimental.UtilityClass;

import java.security.KeyPair;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;

/** Signed registry fixtures with explicit cache boundaries (Token Status List draft 20 §5.1 and §8.3). */
@UtilityClass
public class StatusListTokenFixture {

    /** Preserves the list, subject and signing identity while setting the lifetime the registry advertises. */
    public static String withLifetime(final String token, final KeyPair signingKey,
                                     final Instant expiresAt, final long ttlSeconds) {
        try {
            final SignedJWT original = SignedJWT.parse(token);
            final SignedJWT updated = new SignedJWT(new JWSHeader.Builder(original.getHeader())
                    .customParams(new HashMap<>(original.getHeader().getCustomParams()))
                    .customParam("profile_version", "swiss-profile-vc:1.0.0")
                    .build(), new JWTClaimsSet.Builder(original.getJWTClaimsSet())
                    .expirationTime(Date.from(expiresAt))
                    .claim("ttl", ttlSeconds)
                    .build());
            updated.sign(new ECDSASigner(KeyUtil.createJWKFromKeyPair(signingKey).toECKey()));
            return updated.serialize();
        } catch (ParseException | JOSEException exception) {
            throw new IllegalArgumentException("Cannot sign the status list fixture", exception);
        }
    }
}
