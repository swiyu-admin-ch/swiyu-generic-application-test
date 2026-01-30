package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.issuer_metadata;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;

import java.util.List;
import java.util.Set;

@Slf4j
public final class IssuerMetadataAssert {

    private final IssuerMetadata metadata;
    private final JsonObject data;

    private IssuerMetadataAssert(final IssuerMetadata metadata) {
        this.metadata = metadata;
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
        Assertions.assertThat(data.has("credential_request_encryption"))
                .as("credential_request_encryption must be present")
                .isTrue();

        final JsonObject enc = data.getAsJsonObject("credential_request_encryption");

        Assertions.assertThat(enc.has("jwks"))
                .as("credential_request_encryption.jwks must be present")
                .isTrue();

        final JsonObject jwks = enc.getAsJsonObject("jwks");

        Assertions.assertThat(jwks.has("keys"))
                .as("jwks.keys must be present")
                .isTrue();

        Assertions.assertThat(jwks.getAsJsonArray("keys"))
                .as("jwks.keys must not be empty")
                .isNotEmpty();

        jwks.getAsJsonArray("keys").forEach(k -> Assertions.assertThat(k.getAsJsonObject().has("kid"))
                .as("Each JWK must contain a kid")
                .isTrue());

        Assertions.assertThat(enc.has("enc_values_supported"))
                .as("credential_request_encryption.enc_values_supported must be present")
                .isTrue();

        expectedEncValues
                .forEach(expected -> Assertions.assertThat(enc.getAsJsonArray("enc_values_supported").toString())
                        .as("enc_values_supported must contain %s", expected)
                        .contains(expected));

        if (expectedZipValues != null && !expectedZipValues.isEmpty()) {
            Assertions.assertThat(enc.has("zip_values_supported"))
                    .as("credential_request_encryption.zip_values_supported must be present")
                    .isTrue();

            expectedZipValues
                    .forEach(expected -> Assertions.assertThat(enc.getAsJsonArray("zip_values_supported").toString())
                            .as("zip_values_supported must contain %s", expected)
                            .contains(expected));
        }

        return this;
    }

    public IssuerMetadataAssert supportsCredentialResponseEncryption(
            final List<String> expectedAlgValues,
            final List<String> expectedEncValues,
            final List<String> expectedZipValues) {
        Assertions.assertThat(data.has("credential_response_encryption"))
                .as("credential_response_encryption must be present")
                .isTrue();

        final JsonObject enc = data.getAsJsonObject("credential_response_encryption");

        Assertions.assertThat(enc.has("alg_values_supported"))
                .as("credential_response_encryption.alg_values_supported must be present")
                .isTrue();

        expectedAlgValues
                .forEach(expected -> Assertions.assertThat(enc.getAsJsonArray("alg_values_supported").toString())
                        .as("alg_values_supported must contain %s", expected)
                        .contains(expected));

        Assertions.assertThat(enc.has("enc_values_supported"))
                .as("credential_response_encryption.enc_values_supported must be present")
                .isTrue();

        expectedEncValues
                .forEach(expected -> Assertions.assertThat(enc.getAsJsonArray("enc_values_supported").toString())
                        .as("enc_values_supported must contain %s", expected)
                        .contains(expected));

        if (expectedZipValues != null && !expectedZipValues.isEmpty()) {
            Assertions.assertThat(enc.has("zip_values_supported"))
                    .as("credential_response_encryption.zip_values_supported must be present")
                    .isTrue();

            expectedZipValues
                    .forEach(expected -> Assertions.assertThat(enc.getAsJsonArray("zip_values_supported").toString())
                            .as("zip_values_supported must contain %s", expected)
                            .contains(expected));
        }

        return this;
    }

    public IssuerMetadataAssert requiresCredentialRequestEncryption() {
        Assertions.assertThat(
                data.getAsJsonObject("credential_request_encryption")
                        .get("encryption_required")
                        .getAsBoolean())
                .as("credential_request_encryption.encryption_required must be true")
                .isTrue();

        return this;
    }

    public IssuerMetadataAssert requiresCredentialResponseEncryption() {
        Assertions.assertThat(
                data.getAsJsonObject("credential_response_encryption")
                        .get("encryption_required")
                        .getAsBoolean())
                .as("credential_response_encryption.encryption_required must be true")
                .isTrue();

        return this;
    }

}
