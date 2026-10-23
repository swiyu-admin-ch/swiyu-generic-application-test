package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto;

import ch.admin.bj.swiyu.gen.verifier.model.JsonWebKey;
import com.nimbusds.jose.CompressionAlgorithm;
import com.nimbusds.jose.JWEObject;
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

    // Technical defaults of the issuer/verifier containers, separate from Swiss Wallet interoperability capacities.
    public static final int DEFAULT_JWE_DECOMPRESSED_PAYLOAD_LIMIT_BYTES = 20 * MEBIBYTE;
    public static final int DEFAULT_JWE_COMPRESSED_CIPHER_TEXT_LIMIT_CHARACTERS = 20 * MEBIBYTE;
    // Swiss verification profile §13, Authorization Response Size: MB is expressed in decimal bytes here.
    public static final int SWISS_AUTHORIZATION_RESPONSE_SIZE_BYTES = 21_000_000;
    // A lower bound for the oversized-body fixture; this is not an asserted HTTP server configuration.
    private static final int OVERSIZED_BODY_FIXTURE_THRESHOLD_BYTES = 25 * MEBIBYTE;

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
        } catch (ParseException ex) {
            throw new AssertionError("Expected payload to be a valid encrypted JWE, but parsing failed: " + ex.getMessage(), ex);
        }
    }

    public static String createDecompressedJsonPayloadAtSize(
            final String baseJson,
            final int targetBytes,
            final PayloadEncoding encoding
    ) {
        return createJsonPayload(baseJson, targetBytes, encoding, false);
    }

    public static String createOversizedJsonPayload(final String baseJson) {
        return createJsonPayload(
                baseJson,
                OVERSIZED_COMPACT_JWE_PLAINTEXT_BYTES,
                PayloadEncoding.ASCII,
                true
        );
    }

    public static String createIncompressibleJsonPayloadAtSize(final String baseJson, final int targetBytes) {
        return createJsonPayload(baseJson, targetBytes, PayloadEncoding.ASCII, true);
    }

    private static String createJsonPayload(
            final String baseJson,
            final int targetBytes,
            final PayloadEncoding encoding,
            final boolean incompressible
    ) {
        final int closingBrace = baseJson.lastIndexOf('}');
        if (closingBrace < 0 || !baseJson.substring(closingBrace + 1).isBlank()) {
            throw new IllegalArgumentException("Expected a JSON object as base payload");
        }

        final String jsonWithoutClosingBrace = baseJson.substring(0, closingBrace);
        final String separator = jsonWithoutClosingBrace.stripTrailing().endsWith("{") ? "" : ",";
        final String prefix = jsonWithoutClosingBrace + separator + JSON_PADDING_PROPERTY;
        final String suffix = "\"}";
        final int paddingBytes = targetBytes - utf8Length(prefix) - utf8Length(suffix);
        if (paddingBytes <= 0) {
            throw new IllegalArgumentException("JSON framing exceeds the target payload size");
        }

        final String padding = incompressible
                ? createIncompressibleAsciiPadding(paddingBytes)
                : createCompressiblePadding(paddingBytes, encoding);
        final String payload = prefix + padding + suffix;

        assertThat(utf8Length(payload))
                .as("Decompressed JWE payload size for %s", encoding)
                .isEqualTo(targetBytes);
        if (encoding == PayloadEncoding.MULTIBYTE_UTF8) {
            assertThat(payload.length())
                    .as("UTF-8 scenario must detect Java character-count limits")
                    .isLessThan(targetBytes);
        }
        return payload;
    }

    public static void assertDecompressedPayloadAtSize(
            final String plaintext,
            final String compactJwe,
            final int expectedDecompressedBytes
    ) {
        final JWEObject jweObject = parseAndAssertDeflatedJwe(compactJwe);

        final int compressedCipherTextCharacters = jweObject.getCipherText().toString().length();
        assertThat(utf8Length(plaintext))
                .as("Decompressed JWE payload boundary")
                .isEqualTo(expectedDecompressedBytes);
        assertThat(utf8Length(compactJwe))
                .as("A boundary payload must remain smaller than the oversized-body fixture")
                .isLessThan(OVERSIZED_BODY_FIXTURE_THRESHOLD_BYTES);
        assertThat(compressedCipherTextCharacters)
                .as("A decompressed-size test must respect the ciphertext limit in Base64URL characters")
                .isLessThanOrEqualTo(DEFAULT_JWE_COMPRESSED_CIPHER_TEXT_LIMIT_CHARACTERS);
    }

    public static void assertOversizedEncryptedPayload(
            final String plaintext,
            final String compactJwe
    ) {
        final JWEObject jweObject = parseAndAssertDeflatedJwe(compactJwe);
        assertThat(utf8Length(plaintext))
                .as("Oversized-body scenario plaintext size")
                .isEqualTo(OVERSIZED_COMPACT_JWE_PLAINTEXT_BYTES);
        assertThat(utf8Length(compactJwe))
                .as("Oversized compact JWE content size")
                .isGreaterThan(OVERSIZED_BODY_FIXTURE_THRESHOLD_BYTES);
        assertThat(jweObject.getCipherText().toString().length())
                .as("Oversized-body scenario ciphertext length in Base64URL characters")
                .isGreaterThan(DEFAULT_JWE_COMPRESSED_CIPHER_TEXT_LIMIT_CHARACTERS);
    }

    private static JWEObject parseAndAssertDeflatedJwe(final String compactJwe) {
        assertIsJWE(compactJwe);
        try {
            final JWEObject jweObject = JWEObject.parse(compactJwe);
            assertThat(jweObject.getHeader().getCompressionAlgorithm())
                    .as("JWE compression algorithm")
                    .isEqualTo(CompressionAlgorithm.DEF);
            return jweObject;
        } catch (ParseException ex) {
            throw new AssertionError("Expected a parseable compact JWE", ex);
        }
    }

    private static String createCompressiblePadding(
            final int paddingBytes,
            final PayloadEncoding encoding
    ) {
        final int encodedCharacterCount = paddingBytes / encoding.utf8BytesPerCharacter;
        final int remainingAsciiBytes = paddingBytes % encoding.utf8BytesPerCharacter;
        return encoding.character.repeat(encodedCharacterCount) + "A".repeat(remainingAsciiBytes);
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

    public enum PayloadEncoding {
        ASCII("A", 1),
        MULTIBYTE_UTF8("€", 3);

        private final String character;
        private final int utf8BytesPerCharacter;

        PayloadEncoding(final String character, final int utf8BytesPerCharacter) {
            this.character = character;
            this.utf8BytesPerCharacter = utf8BytesPerCharacter;
        }
    }
}
