package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import ch.admin.bj.swiyu.gen.verifier.model.JsonWebKey;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
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
