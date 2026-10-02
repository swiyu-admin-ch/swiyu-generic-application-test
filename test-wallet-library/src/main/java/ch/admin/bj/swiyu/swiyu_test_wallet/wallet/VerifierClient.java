package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.gen.verifier.model.DcqlQueryDto;
import ch.admin.bj.swiyu.gen.verifier.model.JsonWebKey;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.exceptions.WalletEncryptionException;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto.JWESupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto.WalletJwe;
import com.google.gson.Gson;
import com.nimbusds.jose.jwk.ECKey;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.util.*;

import static ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet.*;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * What the Wallet says to a Verifier (OID4VP 1.0): fetching the Request Object, resolving its DCQL query, and sending the
 * Authorization Response (`vp_token`, `direct_post` or `direct_post.jwt`) or an error.
 * It reads the wallet's current settings (profile, service location, trust configuration) on every call.
 */
final class VerifierClient {

    private final Wallet wallet;

    private static final VerificationQueryResolver VERIFICATION_QUERY_RESOLVER = new VerificationQueryResolver();

    private final ObjectMapper objectMapper = JsonMapper.builder()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    VerifierClient(final Wallet wallet) {
        this.wallet = wallet;
    }

    public VerificationRequestObject getVerificationDetails(String verificationDeeplink) {
        var query = URI.create(verificationDeeplink).getQuery();
        String[] pairs = query.split("&");

        var verificationUrl =
                wallet.getVerifierContext().getContextualizedUri(
                        PathSupport.toUri(pairs[1].split("=")[1])
                );

        ResponseEntity<String> response = wallet.getRestClient().get()
                .uri(verificationUrl)
                .header(
                        HttpHeaders.ACCEPT,
                        "application/oauth-authz-req+jwt, application/json"
                )
                .retrieve()
                .toEntity(String.class);

        MediaType contentType = response.getHeaders().getContentType();
        String body = response.getBody();

        assertThat(body).isNotNull();

        if (MediaType.valueOf("application/oauth-authz-req+jwt").includes(contentType)) {
            return new VerificationRequestObject.Signed(body);
        }

        try {
            final ObjectMapper mapper = JsonMapper.builder()
                    .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                    .build();
            final RequestObject requestObject =
                    mapper.readValue(body, RequestObject.class);
            return new VerificationRequestObject.Unsigned(requestObject);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse unsigned request object", e);
        }
    }
    private RequestObject readSignedRequestObject(String jwt) {
        try {
            String[] parts = jwt.split("\\.");

            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid JWT format");
            }

            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);

            return objectMapper.readValue(payload, RequestObject.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to read signed request object", e);
        }
    }
    public RequestObject getVerificationRequestObject(String verificationDeeplink) {
        VerificationRequestObject request = getVerificationDetails(verificationDeeplink);
        return readSignedRequestObject(((VerificationRequestObject.Signed) request).jwt());
    }
    public String getVerificationDetailSigned(String verificationDeeplink) {
        VerificationRequestObject request = getVerificationDetails(verificationDeeplink);
        return ((VerificationRequestObject.Signed) request).jwt();
    }
    public Optional<URI> respondToVerification(RequestObject requestObject, String token) {
        final ResponseEntity<String> response = respondToVerificationWithVpTokens(requestObject, List.of(token));

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        return readRedirectUri(response);
    }
    public ResponseEntity<String> respondToVerificationWithVpTokens(
            final RequestObject requestObject,
            final List<String> tokens
    ) {
        final String tokenId = resolveVerificationQuery(requestObject)
                .getCredentials()
                .getFirst()
                .getId();
        final Map<String, Object> vpToken = Map.of(tokenId, tokens);

        final MultiValueMap<String, Object> formData = new LinkedMultiValueMap<>();

        if (wallet.getProfile().encryption()) {
            formData.add("response", buildEncryptedResponse(requestObject, vpToken));
        } else {
            formData.add(VP_TOKEN, new Gson().toJson(vpToken));

            if (requestObject.getState() != null) {
                formData.add(STATE, requestObject.getState());
            }
        }

        return wallet.getRestClient().post()
                .uri(wallet.getVerifierContext().getContextualizedUri(PathSupport.toUri(requestObject.getResponseUri())))
                .headers(headers -> {
                    headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
                    headers.add(SWIYU_API_VERSION_HEADER, SwiyuApiVersionConfig.V1.getValue());
                })
                .body(formData)
                .retrieve()
                .toEntity(String.class);
    }
    DcqlQueryDto resolveVerificationQuery(final RequestObject requestObject) {
        return VERIFICATION_QUERY_RESOLVER.resolve(requestObject, wallet.getTrustConfig());
    }
    public Optional<URI> respondToVerificationWithError(
            final RequestObject requestObject,
            final String error,
            final String errorDescription
    ) {
        return respondToVerificationWithError(
                PathSupport.toUri(requestObject.getResponseUri()),
                requestObject.getState(),
                error,
                errorDescription
        );
    }
    public Optional<URI> respondToVerificationWithError(
            final URI responseUri,
            final String state,
            final String error,
            final String errorDescription
    ) {
        final MultiValueMap<String, Object> formData = new LinkedMultiValueMap<>();
        formData.add("error", error);

        if (errorDescription != null) {
            formData.add("error_description", errorDescription);
        }

        if (state != null) {
            formData.add(STATE, state);
        }

        final ResponseEntity<String> response = wallet.getRestClient().post()
                .uri(wallet.getVerifierContext().getContextualizedUri(responseUri))
                .headers(headers -> {
                    headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
                    headers.add(SWIYU_API_VERSION_HEADER, SwiyuApiVersionConfig.V1.getValue());
                })
                .body(formData)
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        return readRedirectUri(response);
    }
    private Optional<URI> readRedirectUri(ResponseEntity<String> response) {
        if (response.getStatusCode().value() != 200 || response.getBody() == null || response.getBody().isBlank()) {
            return Optional.empty();
        }

        assertThat(response.getHeaders().getContentType())
                .as("OID4VP Response Endpoint Content-Type")
                .isNotNull()
                .matches(MediaType.APPLICATION_JSON::isCompatibleWith);

        try {
            final JsonNode redirectUriNode = objectMapper.readTree(response.getBody()).get("redirect_uri");
            if (redirectUriNode == null || redirectUriNode.isNull()) {
                return Optional.empty();
            }

            final URI redirectUri = URI.create(redirectUriNode.asText());
            if (!redirectUri.isAbsolute()) {
                throw new IllegalArgumentException("redirect_uri must be an absolute URI");
            }
            return Optional.of(redirectUri);
        } catch (JacksonException e) {
            throw new IllegalArgumentException("Unable to process redirect_uri from verifier response", e);
        }
    }
    private String buildEncryptedResponse(final RequestObject requestObject, final Map<String, Object> payload) {
        try {
            final JsonWebKey jsonWebKey = requestObject.getClientMetadata()
                    .getJwks()
                    .getKeys()
                    .getFirst();
            final ECKey verifierPublicKey = JWESupport.toECKey(jsonWebKey);
            final Map<String, Object> responsePayload = new LinkedHashMap<>();
            responsePayload.put(VP_TOKEN, payload);
            if (requestObject.getState() != null) {
                responsePayload.put(STATE, requestObject.getState());
            }
            final String vpTokenPayload =
                    new ObjectMapper().writeValueAsString(responsePayload);
            return WalletJwe.encrypt(vpTokenPayload, verifierPublicKey);
        } catch (Exception e) {
            throw new WalletEncryptionException("Failed to build encrypted VP token response (JWE creation failed)", e);
        }
    }
}
