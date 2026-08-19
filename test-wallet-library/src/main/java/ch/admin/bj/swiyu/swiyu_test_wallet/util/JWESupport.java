package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import ch.admin.bj.swiyu.gen.verifier.model.JsonWebKey;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import lombok.experimental.UtilityClass;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

@UtilityClass
public class JWESupport {

    private static final int MEBIBYTE = 1_024 * 1_024;
    private static final int OVERSIZED_DECOMPRESSED_PAYLOAD_BYTES = 21 * MEBIBYTE + 1;

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

    /**
     * Creates a valid JSON payload with highly compressible content whose UTF-8 representation exceeds both
     * the 20 MiB JWE limit and the 21 MiB Verifier interoperability recommendation by one byte.
     */
    public static String createDecompressionBombPayload(
            final String prefix,
            final String suffix,
            final DecompressionBombEncoding encoding
    ) {
        final int framingBytes = utf8Length(prefix) + utf8Length(suffix);
        final int paddingBytes = OVERSIZED_DECOMPRESSED_PAYLOAD_BYTES - framingBytes;
        if (paddingBytes <= 0) {
            throw new IllegalArgumentException("JSON framing exceeds the target payload size");
        }

        final int encodedCharacterCount = paddingBytes / encoding.utf8BytesPerCharacter;
        final int remainingAsciiBytes = paddingBytes % encoding.utf8BytesPerCharacter;
        final String payload = prefix
                + encoding.character.repeat(encodedCharacterCount)
                + "A".repeat(remainingAsciiBytes)
                + suffix;

        assertThat(utf8Length(payload))
                .as("Decompressed JWE payload size")
                .isEqualTo(OVERSIZED_DECOMPRESSED_PAYLOAD_BYTES);
        if (encoding == DecompressionBombEncoding.MULTIBYTE_UTF8) {
            assertThat(payload.length())
                    .as("UTF-8 scenario must detect Java character-count limits")
                    .isLessThan(20 * MEBIBYTE);
        }
        return payload;
    }

    private static int utf8Length(final String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    public enum DecompressionBombEncoding {
        ASCII("A", 1),
        MULTIBYTE_UTF8("€", 3);

        private final String character;
        private final int utf8BytesPerCharacter;

        DecompressionBombEncoding(final String character, final int utf8BytesPerCharacter) {
            this.character = character;
            this.utf8BytesPerCharacter = utf8BytesPerCharacter;
        }
    }
}
