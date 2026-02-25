package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.request_object;

import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.ResponseModeType;
import ch.admin.bj.swiyu.gen.verifier.model.OpenidClientMetadataDto;
import org.assertj.core.api.Assertions;

public final class RequestObjectAssert {

    private final RequestObject requestObject;

    private RequestObjectAssert(final RequestObject requestObject) {
        this.requestObject = requestObject;
    }

    public static RequestObjectAssert assertThat(final RequestObject requestObject) {
        return new RequestObjectAssert(requestObject);
    }

    public RequestObjectAssert hasClientId() {
        Assertions.assertThat(requestObject.getClientId())
                .as("request object client_id")
                .isNotNull()
                .isNotBlank();
        return this;
    }

    public RequestObjectAssert hasClientId(final String expectedClientId) {
        Assertions.assertThat(requestObject.getClientId())
                .as("request object client_id")
                .isEqualTo(expectedClientId);
        return this;
    }

    public RequestObjectAssert hasClientIdScheme(final String expectedScheme) {
        Assertions.assertThat(requestObject.getClientIdScheme())
                .as("request object client_id_scheme")
                .isEqualTo(expectedScheme);
        return this;
    }

    public RequestObjectAssert hasResponseType(final String expectedResponseType) {
        Assertions.assertThat(requestObject.getResponseType())
                .as("request object response_type")
                .isEqualTo(expectedResponseType);
        return this;
    }

    public RequestObjectAssert hasResponseMode(final ResponseModeType expectedResponseMode) {
        Assertions.assertThat(requestObject.getResponseMode())
                .as("request object response_mode")
                .isEqualTo(expectedResponseMode);
        return this;
    }

    public RequestObjectAssert hasResponseUri() {
        Assertions.assertThat(requestObject.getResponseUri())
                .as("request object response_uri")
                .isNotNull()
                .isNotBlank();
        return this;
    }

    public RequestObjectAssert hasNonce() {
        Assertions.assertThat(requestObject.getNonce())
                .as("request object nonce")
                .isNotNull()
                .isNotBlank();
        return this;
    }

    public RequestObjectAssert hasDcqlQuery() {
        Assertions.assertThat(requestObject.getDcqlQuery())
                .as("request object dcql_query")
                .isNotNull();
        return this;
    }

    public RequestObjectAssert hasPresentationDefinition() {
        Assertions.assertThat(requestObject.getPresentationDefinition())
                .as("request object presentation_definition")
                .isNotNull();
        return this;
    }

    public RequestObjectAssert hasClientMetadata() {
        Assertions.assertThat(requestObject.getClientMetadata())
                .as("request object client_metadata")
                .isNotNull();
        return this;
    }

    public RequestObjectAssert hasState() {
        Assertions.assertThat(requestObject.getState())
                .as("request object state")
                .isNotNull()
                .isNotBlank();
        return this;
    }

    public RequestObjectAssert hasEncryptionJwks() {
        final OpenidClientMetadataDto metadata = requestObject.getClientMetadata();
        Assertions.assertThat(metadata)
                .as("client_metadata required for encryption")
                .isNotNull();

        Assertions.assertThat(metadata.getJwks())
                .as("jwks in client_metadata required for encryption")
                .isNotNull();

        Assertions.assertThat(metadata.getJwks().getKeys())
                .as("jwks.keys must contain encryption public keys")
                .isNotEmpty();

        return this;
    }

    public RequestObjectAssert hasEncryptionJwksWithAlgorithm(final String expectedAlgorithm) {
        final OpenidClientMetadataDto metadata = requestObject.getClientMetadata();

        Assertions.assertThat(metadata.getJwks()).isNotNull();
        Assertions.assertThat(metadata.getJwks().getKeys())
                .isNotEmpty();

        metadata.getJwks().getKeys().forEach(jwk ->
                Assertions.assertThat(jwk.getAlg())
                        .as("JWK alg parameter must match expected algorithm (spec 8.3)")
                        .isEqualTo(expectedAlgorithm)
        );

        return this;
    }

    public RequestObjectAssert hasEncryptionJwksWithKty(final String expectedKeyType) {
        final OpenidClientMetadataDto metadata = requestObject.getClientMetadata();

        Assertions.assertThat(metadata.getJwks()).isNotNull();
        Assertions.assertThat(metadata.getJwks().getKeys())
                .isNotEmpty();

        metadata.getJwks().getKeys().forEach(jwk ->
                Assertions.assertThat(jwk.getKty())
                        .as("JWK kty (Key Type) must match expected type")
                        .isEqualTo(expectedKeyType)
        );

        return this;
    }

    public RequestObjectAssert hasEncryptionJwksWithCurve(final String expectedCurve) {
        final OpenidClientMetadataDto metadata = requestObject.getClientMetadata();

        Assertions.assertThat(metadata.getJwks()).isNotNull();
        Assertions.assertThat(metadata.getJwks().getKeys())
                .isNotEmpty();

        metadata.getJwks().getKeys().forEach(jwk ->
                Assertions.assertThat(jwk.getCrv())
                        .as("JWK crv (Curve) must match expected curve")
                        .isEqualTo(expectedCurve)
        );

        return this;
    }

    public RequestObjectAssert hasEncryptionEncAlgorithm(final String expectedEncAlgorithm) {
        final OpenidClientMetadataDto metadata = requestObject.getClientMetadata();

        Assertions.assertThat(metadata.getEncryptedResponseEncValuesSupported())
                .as("encrypted_response_enc_values_supported must contain encryption algorithm")
                .isNotNull()
                .contains(expectedEncAlgorithm);

        return this;
    }

    public RequestObjectAssert hasVpFormats() {
        final OpenidClientMetadataDto metadata = requestObject.getClientMetadata();

        Assertions.assertThat(metadata)
                .isNotNull();

        return this;
    }
}

