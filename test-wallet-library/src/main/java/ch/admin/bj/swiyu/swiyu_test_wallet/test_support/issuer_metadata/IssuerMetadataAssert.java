package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.issuer_metadata;

import com.google.gson.JsonObject;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;

import java.util.List;

@Slf4j
public final class IssuerMetadataAssert {

    private final JsonObject data;

    private static final String KEY_CREDENTIAL_REQUEST_ENCRYPTION = "credential_request_encryption";
    private static final String KEY_CREDENTIAL_RESPONSE_ENCRYPTION = "credential_response_encryption";
    private static final String KEY_JWKS = "jwks";
    private static final String KEY_KEYS = "keys";
    private static final String KEY_KID = "kid";
    private static final String KEY_ALG_VALUES_SUPPORTED = "alg_values_supported";
    private static final String KEY_ENC_VALUES_SUPPORTED = "enc_values_supported";
    private static final String KEY_ZIP_VALUES_SUPPORTED = "zip_values_supported";
    private static final String KEY_ENCRYPTION_REQUIRED = "encryption_required";

    private IssuerMetadataAssert(final IssuerMetadata metadata) {
        this.data = metadata.getData();
    }

    public static IssuerMetadataAssert assertThat(final IssuerMetadata metadata) {
        Assertions.assertThat(metadata)
                .as("IssuerMetadata must not be null")
                .isNotNull();

        Assertions.assertThat(metadata.getData())
                .as("IssuerMetadata.data must not be null")
                .isNotNull();

        log.debug("IssuerMetadata: {}", metadata.getData());

        return new IssuerMetadataAssert(metadata);
    }

    public IssuerMetadataAssert supportsCredentialRequestEncryption(
            final List<String> expectedEncValues,
            final List<String> expectedZipValues) {

        Assertions.assertThat(data.has(KEY_CREDENTIAL_REQUEST_ENCRYPTION))
                .as("credential_request_encryption must be present")
                .isTrue();

        final JsonObject enc = data.getAsJsonObject(KEY_CREDENTIAL_REQUEST_ENCRYPTION);

        Assertions.assertThat(enc.has(KEY_JWKS))
                .as("credential_request_encryption.jwks must be present")
                .isTrue();

        final JsonObject jwks = enc.getAsJsonObject(KEY_JWKS);

        Assertions.assertThat(jwks.has(KEY_KEYS))
                .as("jwks.keys must be present")
                .isTrue();

        Assertions.assertThat(jwks.getAsJsonArray(KEY_KEYS))
                .as("jwks.keys must not be empty")
                .isNotEmpty();

        jwks.getAsJsonArray(KEY_KEYS).forEach(k ->
                Assertions.assertThat(k.getAsJsonObject().has(KEY_KID))
                        .as("Each JWK must contain a kid")
                        .isTrue()
        );

        Assertions.assertThat(enc.has(KEY_ENC_VALUES_SUPPORTED))
                .as("credential_request_encryption.enc_values_supported must be present")
                .isTrue();

        expectedEncValues.forEach(expected ->
                Assertions.assertThat(enc.getAsJsonArray(KEY_ENC_VALUES_SUPPORTED).toString())
                        .as("enc_values_supported must contain %s", expected)
                        .contains(expected)
        );

        if (expectedZipValues != null && !expectedZipValues.isEmpty()) {
            Assertions.assertThat(enc.has(KEY_ZIP_VALUES_SUPPORTED))
                    .as("credential_request_encryption.zip_values_supported must be present")
                    .isTrue();

            expectedZipValues.forEach(expected ->
                    Assertions.assertThat(enc.getAsJsonArray(KEY_ZIP_VALUES_SUPPORTED).toString())
                            .as("zip_values_supported must contain %s", expected)
                            .contains(expected)
            );
        }

        return this;
    }

    public IssuerMetadataAssert supportsCredentialResponseEncryption(
            final List<String> expectedAlgValues,
            final List<String> expectedEncValues,
            final List<String> expectedZipValues) {

        Assertions.assertThat(data.has(KEY_CREDENTIAL_RESPONSE_ENCRYPTION))
                .as("credential_response_encryption must be present")
                .isTrue();

        final JsonObject enc = data.getAsJsonObject(KEY_CREDENTIAL_RESPONSE_ENCRYPTION);

        Assertions.assertThat(enc.has(KEY_ALG_VALUES_SUPPORTED))
                .as("credential_response_encryption.alg_values_supported must be present")
                .isTrue();

        expectedAlgValues.forEach(expected ->
                Assertions.assertThat(enc.getAsJsonArray(KEY_ALG_VALUES_SUPPORTED).toString())
                        .as("alg_values_supported must contain %s", expected)
                        .contains(expected)
        );

        Assertions.assertThat(enc.has(KEY_ENC_VALUES_SUPPORTED))
                .as("credential_response_encryption.enc_values_supported must be present")
                .isTrue();

        expectedEncValues.forEach(expected ->
                Assertions.assertThat(enc.getAsJsonArray(KEY_ENC_VALUES_SUPPORTED).toString())
                        .as("enc_values_supported must contain %s", expected)
                        .contains(expected)
        );

        if (expectedZipValues != null && !expectedZipValues.isEmpty()) {
            Assertions.assertThat(enc.has(KEY_ZIP_VALUES_SUPPORTED))
                    .as("credential_response_encryption.zip_values_supported must be present")
                    .isTrue();

            expectedZipValues.forEach(expected ->
                    Assertions.assertThat(enc.getAsJsonArray(KEY_ZIP_VALUES_SUPPORTED).toString())
                            .as("zip_values_supported must contain %s", expected)
                            .contains(expected)
            );
        }

        return this;
    }

    public IssuerMetadataAssert requiresCredentialRequestEncryption() {
        Assertions.assertThat(
                        data.getAsJsonObject(KEY_CREDENTIAL_REQUEST_ENCRYPTION)
                                .get(KEY_ENCRYPTION_REQUIRED)
                                .getAsBoolean())
                .as("credential_request_encryption.encryption_required must be true")
                .isTrue();

        return this;
    }

    public IssuerMetadataAssert requiresCredentialResponseEncryption() {
        Assertions.assertThat(
                        data.getAsJsonObject(KEY_CREDENTIAL_RESPONSE_ENCRYPTION)
                                .get(KEY_ENCRYPTION_REQUIRED)
                                .getAsBoolean())
                .as("credential_response_encryption.encryption_required must be true")
                .isTrue();

        return this;
    }
}
