package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import ch.admin.bj.swiyu.gen.verifier.model.JsonWebKey;
import com.github.dockerjava.zerodep.shaded.org.apache.hc.core5.http.ParseException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.experimental.UtilityClass;

import static org.assertj.core.api.Assertions.assertThat;

@UtilityClass
public class JWESupport {

    public static ECKey toECKey(final JsonWebKey jsonWebKey) {
        return new ECKey.Builder(
                Curve.parse(jsonWebKey.getCrv()),
                new Base64URL(jsonWebKey.getX()),
                new Base64URL(jsonWebKey.getY())
        )
                .keyID(jsonWebKey.getKid())
                .build();
    }

    public static String encryptClaims(ECKey verifierKey, JWEHeader header, JWTClaimsSet claims) {
        try {
            var jweObject = new JWEObject(header, claims.toPayload());
            jweObject.encrypt(new ECDHEncrypter(verifierKey.toECKey()));
            return jweObject.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to encrypt JWT claims with verifier key", e);
        }
    }

    public static String decryptJWE(ECKey walletEphemeralKey, String encryptedResponse) {
        try {
            JWEObject jweObject = JWEObject.parse(encryptedResponse);
            jweObject.decrypt(new ECDHDecrypter(walletEphemeralKey));
            return jweObject.getPayload().toString();
        } catch (JOSEException e) {
            throw new RuntimeException("Unable to decrypt ECDH-ES issuer credential response", e);
        } catch (java.text.ParseException e) {
            throw new RuntimeException(e);
        }
    }

    public static void assertIsJWE(String jwe) {
        assertThat(jwe)
                .as("The response must be a compact JWE")
                .isNotBlank();
        String[] parts = jwe.split("\\.");
        assertThat(parts.length)
                .as("A compact JWE must contain 5 sections separated by '.'")
                .isEqualTo(5);
        try {
            JWEObject.parse(jwe);
        } catch (Exception ex) {
            throw new AssertionError("Expected payload to be a valid encrypted JWE, but parsing failed: " + ex.getMessage());
        }
    }
}
