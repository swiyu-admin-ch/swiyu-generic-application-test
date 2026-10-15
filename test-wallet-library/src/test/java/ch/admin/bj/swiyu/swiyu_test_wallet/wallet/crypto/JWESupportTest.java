package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto;

import com.google.gson.JsonParser;
import com.nimbusds.jose.CompressionAlgorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JWESupportTest {

    @Test
    void createIncompressibleJsonPayloadAtSize_whenEncrypted_thenPreservesClaimsAndExceedsCiphertextLimit()
            throws Exception {
        final String baseJson = "{\"state\":\"nonce-€\",\"error\":\"access_denied\"}";
        final int targetBytes = 100 * 1_024;

        final String payload = JWESupport.createIncompressibleJsonPayloadAtSize(baseJson, targetBytes);

        assertThat(payload.getBytes(StandardCharsets.UTF_8))
                .hasSize(targetBytes);
        final var json = JsonParser.parseString(payload).getAsJsonObject();
        assertThat(json.get("state").getAsString())
                .isEqualTo("nonce-€");
        assertThat(json.get("error").getAsString())
                .isEqualTo("access_denied");
        final var key = new ECKeyGenerator(Curve.P_256).generate();
        final String encrypted = WalletJwe.encrypt(payload, key.toPublicJWK());
        assertThat(JWEObject.parse(encrypted).getCipherText().toString().length())
                .as("The random padding must survive compression to exercise the ciphertext limit")
                .isGreaterThan(65_536);
    }

    @ParameterizedTest
    @EnumSource(JWESupport.PayloadEncoding.class)
    void createDecompressedJsonPayloadAtSize_whenEncodingChanges_thenPreservesClaimsAndExactByteSize(
            final JWESupport.PayloadEncoding encoding
    ) {
        final String baseJson = "{\"state\":\"nonce-€\",\"vp_token\":{\"credential\":[\"sd-jwt\"]}}";
        final int targetBytes = 4_096;

        final String payload = JWESupport.createDecompressedJsonPayloadAtSize(baseJson, targetBytes, encoding);

        assertThat(payload.getBytes(StandardCharsets.UTF_8))
                .hasSize(targetBytes);
        final var json = JsonParser.parseString(payload).getAsJsonObject();
        assertThat(json.get("state").getAsString())
                .isEqualTo("nonce-€");
        assertThat(json.getAsJsonObject("vp_token").getAsJsonArray("credential").get(0).getAsString())
                .isEqualTo("sd-jwt");
        assertThat(json.get("padding").getAsString())
                .isNotEmpty();
        if (encoding == JWESupport.PayloadEncoding.MULTIBYTE_UTF8) {
            assertThat(payload.length())
                    .isLessThan(targetBytes);
        }
    }

    @Test
    void assertDecompressedPayloadAtSize_whenCiphertextIsAtCharacterLimit_thenAccepts() {
        final String plaintext = "{\"state\":\"s\"}";
        final String compact = syntheticCompactJwe(
                JWESupport.DEFAULT_JWE_COMPRESSED_CIPHER_TEXT_LIMIT_CHARACTERS);

        JWESupport.assertDecompressedPayloadAtSize(
                plaintext, compact, plaintext.getBytes(StandardCharsets.UTF_8).length);
    }

    @Test
    void assertDecompressedPayloadAtSize_whenCiphertextExceedsCharacterLimit_thenRejects() throws Exception {
        final String plaintext = "{\"state\":\"s\"}";
        final String compact = syntheticCompactJwe(
                JWESupport.DEFAULT_JWE_COMPRESSED_CIPHER_TEXT_LIMIT_CHARACTERS + 2);

        // Decoded ciphertext bytes would incorrectly pass the old fixture check.
        assertThat(JWEObject.parse(compact).getCipherText().decode().length)
                .isLessThan(JWESupport.DEFAULT_JWE_COMPRESSED_CIPHER_TEXT_LIMIT_CHARACTERS);
        assertThatThrownBy(() -> JWESupport.assertDecompressedPayloadAtSize(
                plaintext, compact, plaintext.getBytes(StandardCharsets.UTF_8).length))
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("Base64URL characters");
    }

    private String syntheticCompactJwe(final int ciphertextCharacters) {
        final JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                .compressionAlgorithm(CompressionAlgorithm.DEF)
                .build();
        // This fixture exercises serialization lengths only; it is never decrypted or sent to a component.
        return header.toBase64URL() + "..AA." + "A".repeat(ciphertextCharacters) + ".AA";
    }
}
