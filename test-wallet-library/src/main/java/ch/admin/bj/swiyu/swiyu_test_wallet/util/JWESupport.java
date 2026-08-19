package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import ch.admin.bj.swiyu.gen.verifier.model.JsonWebKey;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import lombok.experimental.UtilityClass;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

@UtilityClass
public class JWESupport {

    private static final int MEBIBYTE = 1_024 * 1_024;
    private static final int OVERSIZED_COMPACT_JWE_PLAINTEXT_BYTES = 32 * MEBIBYTE + 1;
    private static final String JSON_PADDING_PROPERTY = "\"padding\":\"";
    private static final String RANDOM_JSON_CHARACTERS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_~!@#$%^&*()[]{}:;,.?/";

    public static final int ISSUER_DECOMPRESSED_PAYLOAD_LIMIT_BYTES = 20 * MEBIBYTE;
    public static final int VERIFIER_AUTHORIZATION_RESPONSE_LIMIT_BYTES = 21 * MEBIBYTE;
    public static final int HTTP_CONTENT_LIMIT_BYTES = 25 * MEBIBYTE;

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

    public static String createOversizedJsonPayload(
            final String baseJson,
            final int decompressedPayloadLimitBytes,
            final PayloadSizeScenario scenario
    ) {
        final int closingBrace = baseJson.lastIndexOf('}');
        if (closingBrace < 0 || !baseJson.substring(closingBrace + 1).isBlank()) {
            throw new IllegalArgumentException("Expected a JSON object as base payload");
        }

        final String jsonWithoutClosingBrace = baseJson.substring(0, closingBrace);
        final String separator = jsonWithoutClosingBrace.stripTrailing().endsWith("{") ? "" : ",";
        final String prefix = jsonWithoutClosingBrace + separator + JSON_PADDING_PROPERTY;
        final String suffix = "\"}";
        final int targetBytes = switch (scenario) {
            case COMPACT_JWE_OVER_HTTP_LIMIT -> OVERSIZED_COMPACT_JWE_PLAINTEXT_BYTES;
            default -> decompressedPayloadLimitBytes + 1;
        };
        final int paddingBytes = targetBytes - utf8Length(prefix) - utf8Length(suffix);
        if (paddingBytes <= 0) {
            throw new IllegalArgumentException("JSON framing exceeds the target payload size");
        }

        final String padding = scenario == PayloadSizeScenario.COMPACT_JWE_OVER_HTTP_LIMIT
                ? createIncompressibleAsciiPadding(paddingBytes)
                : createCompressiblePadding(paddingBytes, scenario);
        final String payload = prefix + padding + suffix;

        assertThat(utf8Length(payload))
                .as("Decompressed JWE payload size for %s", scenario)
                .isEqualTo(targetBytes);
        if (scenario == PayloadSizeScenario.DECOMPRESSED_MULTIBYTE_UTF8) {
            assertThat(payload.length())
                    .as("UTF-8 scenario must detect Java character-count limits")
                    .isLessThan(decompressedPayloadLimitBytes);
        }
        return payload;
    }

    public static void assertEncryptedPayloadMatchesScenario(
            final String plaintext,
            final String compactJwe,
            final int decompressedPayloadLimitBytes,
            final PayloadSizeScenario scenario
    ) {
        assertIsJWE(compactJwe);
        final JWEObject jweObject;
        try {
            jweObject = JWEObject.parse(compactJwe);
        } catch (ParseException ex) {
            throw new AssertionError("Expected a parseable compact JWE", ex);
        }
        assertThat(jweObject.getHeader().getCompressionAlgorithm())
                .as("JWE compression algorithm")
                .isEqualTo(CompressionAlgorithm.DEF);

        final int compressedCipherTextBytes = jweObject.getCipherText().decode().length;
        if (scenario == PayloadSizeScenario.COMPACT_JWE_OVER_HTTP_LIMIT) {
            assertThat(utf8Length(compactJwe))
                    .as("HTTP compact JWE content size")
                    .isGreaterThan(HTTP_CONTENT_LIMIT_BYTES);
            assertThat(compressedCipherTextBytes)
                    .as("Compressed JWE ciphertext size")
                    .isGreaterThan(ISSUER_DECOMPRESSED_PAYLOAD_LIMIT_BYTES);
        } else {
            assertThat(utf8Length(plaintext))
                    .as("Decompressed JWE payload boundary")
                    .isEqualTo(decompressedPayloadLimitBytes + 1);
            assertThat(utf8Length(compactJwe))
                    .as("A decompression bomb must stay below the HTTP content limit")
                    .isLessThan(HTTP_CONTENT_LIMIT_BYTES);
            assertThat(compressedCipherTextBytes)
                    .as("A decompression bomb must stay below the compressed-ciphertext limit")
                    .isLessThan(ISSUER_DECOMPRESSED_PAYLOAD_LIMIT_BYTES);
        }
    }

    private static String createCompressiblePadding(
            final int paddingBytes,
            final PayloadSizeScenario scenario
    ) {
        final int encodedCharacterCount = paddingBytes / scenario.utf8BytesPerCharacter;
        final int remainingAsciiBytes = paddingBytes % scenario.utf8BytesPerCharacter;
        return scenario.character.repeat(encodedCharacterCount) + "A".repeat(remainingAsciiBytes);
    }

    private static String createIncompressibleAsciiPadding(final int paddingBytes) {
        final Random random = new Random(0xE1D0_1252L);
        final char[] padding = new char[paddingBytes];
        for (int index = 0; index < padding.length; index++) {
            padding[index] = RANDOM_JSON_CHARACTERS.charAt(random.nextInt(RANDOM_JSON_CHARACTERS.length()));
        }
        return new String(padding);
    }

    private static int utf8Length(final String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    public enum PayloadSizeScenario {
        DECOMPRESSED_ASCII("A", 1),
        DECOMPRESSED_MULTIBYTE_UTF8("€", 3),
        COMPACT_JWE_OVER_HTTP_LIMIT("A", 1);

        private final String character;
        private final int utf8BytesPerCharacter;

        PayloadSizeScenario(final String character, final int utf8BytesPerCharacter) {
            this.character = character;
            this.utf8BytesPerCharacter = utf8BytesPerCharacter;
        }
    }
}
