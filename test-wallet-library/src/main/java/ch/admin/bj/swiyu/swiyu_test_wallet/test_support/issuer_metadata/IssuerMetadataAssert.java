package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.issuer_metadata;

import ch.admin.bj.swiyu.gen.issuer.model.IssuerCredentialRequestEncryption;
import ch.admin.bj.swiyu.gen.issuer.model.IssuerCredentialResponseEncryption;
import ch.admin.bj.swiyu.gen.issuer.model.IssuerMetadata;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;

import java.util.List;
import java.util.Map;

@Slf4j
public final class IssuerMetadataAssert {

    private final IssuerMetadata data;

    private static final String KEY_KEYS = "keys";
    private static final String KEY_KID = "kid";

    private IssuerMetadataAssert(final IssuerMetadata metadata) {
        this.data = metadata;
    }

    public static IssuerMetadataAssert assertThat(final IssuerMetadata metadata) {
        Assertions.assertThat(metadata)
                .as("IssuerMetadata must not be null")
                .isNotNull();

        Assertions.assertThat(metadata)
                .as("IssuerMetadata.data must not be null")
                .isNotNull();

        log.debug("IssuerMetadata: {}", metadata);

        return new IssuerMetadataAssert(metadata);
    }

    public IssuerMetadataAssert supportsCredentialRequestEncryption(
            final List<String> expectedEncValues,
            final List<String> expectedZipValues) {

        Assertions.assertThat(data.getCredentialRequestEncryption())
                .as("credential_request_encryption must be present")
                .isNotNull();

        final IssuerCredentialRequestEncryption enc = data.getCredentialRequestEncryption();

        Assertions.assertThat(enc.getJwks())
                .as("credential_request_encryption.jwks must be present")
                .isNotNull();

        final Map<String, Object> jwks = enc.getJwks();

        Assertions.assertThat(jwks.containsKey(KEY_KEYS))
                .as("jwks.keys must be present")
                .isTrue();

        Assertions.assertThat(jwks.get(KEY_KEYS))
                .as("jwks.keys must not be empty")
                .isNotNull();

        var keysList = (List<?>) jwks.get(KEY_KEYS);
        Assertions.assertThat(keysList)
                .as("jwks.keys must not be empty")
                .isNotEmpty();

        keysList.forEach(k -> {
            var keyMap = (Map<String, Object>) k;
            Assertions.assertThat(keyMap.containsKey(KEY_KID))
                    .as("Each JWK must contain a kid")
                    .isTrue();
        });

        Assertions.assertThat(enc.getEncValuesSupported())
                .as("credential_request_encryption.enc_values_supported must be present")
                .isNotNull()
                .isNotEmpty();

        expectedEncValues.forEach(expected ->
                Assertions.assertThat(enc.getEncValuesSupported())
                        .as("enc_values_supported must contain %s", expected)
                        .contains(expected)
        );

        if (expectedZipValues != null && !expectedZipValues.isEmpty()) {
            Assertions.assertThat(enc.getZipValuesSupported())
                    .as("credential_request_encryption.zip_values_supported must be present")
                    .isNotNull()
                    .isNotEmpty();

            expectedZipValues.forEach(expected ->
                    Assertions.assertThat(enc.getZipValuesSupported())
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

        Assertions.assertThat(data.getCredentialResponseEncryption())
                .as("credential_response_encryption must be present")
                .isNotNull();

        final IssuerCredentialResponseEncryption enc = data.getCredentialResponseEncryption();

        Assertions.assertThat(enc.getAlgValuesSupported())
                .as("credential_response_encryption.alg_values_supported must be present")
                .isNotNull()
                .isNotEmpty();

        expectedAlgValues.forEach(expected ->
                Assertions.assertThat(enc.getAlgValuesSupported())
                        .as("alg_values_supported must contain %s", expected)
                        .contains(expected)
        );

        Assertions.assertThat(enc.getEncValuesSupported())
                .as("credential_response_encryption.enc_values_supported must be present")
                .isNotNull()
                .isNotEmpty();

        expectedEncValues.forEach(expected ->
                Assertions.assertThat(enc.getEncValuesSupported())
                        .as("enc_values_supported must contain %s", expected)
                        .contains(expected)
        );

        if (expectedZipValues != null && !expectedZipValues.isEmpty()) {
            Assertions.assertThat(enc.getZipValuesSupported())
                    .as("credential_response_encryption.zip_values_supported must be present")
                    .isNotNull()
                    .isNotEmpty();

            expectedZipValues.forEach(expected ->
                    Assertions.assertThat(enc.getZipValuesSupported())
                            .as("zip_values_supported must contain %s", expected)
                            .contains(expected)
            );
        }

        return this;
    }

    public IssuerMetadataAssert requiresCredentialRequestEncryption() {
        final IssuerCredentialRequestEncryption enc = data.getCredentialRequestEncryption();
        Assertions.assertThat(enc)
                .as("credential_request_encryption must be present")
                .isNotNull();
        Assertions.assertThat(enc.getEncryptionRequired())
                .as("credential_request_encryption.encryption_required must be true")
                .isTrue();

        return this;
    }

    public IssuerMetadataAssert requiresCredentialResponseEncryption() {
        final IssuerCredentialResponseEncryption enc = data.getCredentialResponseEncryption();
        Assertions.assertThat(enc)
                .as("credential_response_encryption must be present")
                .isNotNull();
        Assertions.assertThat(enc.getEncryptionRequired())
                .as("credential_response_encryption.encryption_required must be true")
                .isTrue();

        return this;
    }
}
