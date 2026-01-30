package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.gen.issuer.model.*;
import ch.admin.bj.swiyu.gen.verifier.model.JsonWebKey;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_response.CredentialResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.issuer_metadata.IssuerMetadata;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JWESupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JwtSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequestObject;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.security.interfaces.ECPrivateKey;
import java.util.*;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.JsonConverter.toJsonNode;
import static org.assertj.core.api.Assertions.assertThat;

@Getter
@Setter
public class Wallet {

    public static final String BEARER_PREFIX = "Bearer ";
    public static final String VC_SD_JWT = "vc+sd-jwt";

    private final RestClient restClient;
    private final ServiceLocationContext issuerContext;
    private final ServiceLocationContext verifierContext;

    private boolean useEncryption = false;
    private boolean signedMetadataPreferred = false;

    public Wallet(RestClient restClient, ServiceLocationContext issuerContext, ServiceLocationContext verifierContext) {
        this.restClient = restClient;
        this.issuerContext = issuerContext;
        this.verifierContext = verifierContext;
    }

    public Wallet(RestClient restClient, ServiceLocationContext issuerContext, ServiceLocationContext verifierContext, boolean useEncryption) {
        this(restClient, issuerContext, verifierContext);
        this.useEncryption = useEncryption;
    }

    public WalletEntry createWalletEntry() {
        return new WalletEntry(this);
    }

    public WalletBatchEntry createWalletBatchEntry() {
        return new WalletBatchEntry(this);
    }

    public String getIssuerTokenUri(WalletEntry walletEntry) {
        return walletEntry.getIssuerTokenUri().toString();
    }

    public String getIssuerCredentialUri(WalletEntry walletEntry) {
        return walletEntry.getIssuerCredentialUri().toString();
    }

    private static String getPresentationSubmissionPayload() {
        return toJsonNode("""
                {
                        "id": "test_ldp_vc_presentation_definition",
                        "definition_id": "test_ldp_vc",
                        "descriptor_map": [{
                            "id": "test_descriptor",
                            "format": "vc+sd-jwt",
                            "path": "$"
                        }]
                    }
                """).toString();
    }

    public WalletEntry collectTransactionIdFromDeferredOffer(final SwiyuApiVersionConfig apiVersion, URI issuerDeepLink) {
        if (apiVersion == SwiyuApiVersionConfig.V1) {
            return collectTransactionIdFromDeferredOfferV1(issuerDeepLink);
        }
        return collectTransactionIdFromDeferredOfferID2(issuerDeepLink);
    }

    private WalletEntry collectTransactionIdFromDeferredOfferID2(URI issuerDeepLink) {
        var walletEntry = createWalletEntry();

        walletEntry.receiveDeepLinkAndValidateIt(issuerDeepLink);
        walletEntry.setIssuerWellKnownConfiguration(getIssuerWellKnownConfiguration(walletEntry));
        walletEntry.setToken(collectToken(walletEntry));
        walletEntry.setIssuerMetadata(getIssuerWellKnownMetadata(walletEntry));
        walletEntry.setCredentialConfigurationSupported();
        CredentialResponse deferredCredentialTransactionIdResponse = postCredentialRequest(SwiyuApiVersionConfig.ID2, walletEntry);

        assertThat(deferredCredentialTransactionIdResponse)
                .isNotNull();

        var transactionIdNode = deferredCredentialTransactionIdResponse.getBody().get("transaction_id");
        assertThat(transactionIdNode).isNotNull();
        var transactionId = transactionIdNode.getAsString();
        assertThat(transactionId).isNotNull();

        walletEntry.setTransactionId(UUID.fromString(transactionId));
        return walletEntry;
    }

    private WalletEntry collectTransactionIdFromDeferredOfferV1(URI issuerDeepLink) {
        var walletBatchEntry = createWalletBatchEntry();

        walletBatchEntry.receiveDeepLinkAndValidateIt(issuerContext.getContextualizedUri(issuerDeepLink));
        walletBatchEntry.setIssuerWellKnownConfiguration(getIssuerWellKnownConfiguration(walletBatchEntry));
        walletBatchEntry.setToken(collectToken(walletBatchEntry));
        walletBatchEntry.setIssuerMetadata(getIssuerWellKnownMetadata(walletBatchEntry));
        walletBatchEntry.setCredentialConfigurationSupported();

        walletBatchEntry.generateHolderKeys();
        walletBatchEntry.createProofs();

        CredentialResponse deferredCredentialTransactionIdResponse = postCredentialRequest(SwiyuApiVersionConfig.V1, walletBatchEntry);

        assertThat(deferredCredentialTransactionIdResponse)
                .isNotNull();

        var transactionIdNode = deferredCredentialTransactionIdResponse.getBody().get("transaction_id");
        assertThat(transactionIdNode).isNotNull();
        var transactionId = transactionIdNode.getAsString();
        assertThat(transactionId).isNotNull();

        walletBatchEntry.setTransactionId(UUID.fromString(transactionId));
        return walletBatchEntry;
    }

    public OpenIdConfiguration getIssuerWellKnownConfiguration(WalletEntry walletEntry) {
        final URI issuerUri = issuerContext.getContextualizedUri(walletEntry.getIssuerUri());
        final URI issuerOpenIdConfiguration = UriComponentsBuilder
                .fromUri(issuerUri)
                .pathSegment(".well-known", "openid-configuration")
                .build()
                .toUri();

        if (this.isSignedMetadataPreferred()) {
            final String jwt = restClient.get()
                    .uri(issuerOpenIdConfiguration)
                    .header(HttpHeaders.ACCEPT, "application/jwt")
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .retrieve()
                    .body(String.class);

            final JsonNode payload = JwtSupport.decodePayloadToJsonNode(jwt);

            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            return objectMapper.convertValue(payload, OpenIdConfiguration.class);
        }

        return restClient.get()
                .uri(issuerOpenIdConfiguration)
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .retrieve()
                .body(OpenIdConfiguration.class);
    }

    public IssuerMetadata getIssuerWellKnownMetadata(WalletEntry walletEntry) {
        final URI issuerUri = issuerContext.getContextualizedUri(walletEntry.getIssuerUri());
        final URI issuerOpenIdCredentialIssuer = UriComponentsBuilder
                .fromUri(issuerUri)
                .pathSegment(".well-known", "openid-credential-issuer")
                .build()
                .toUri();

        if (this.isSignedMetadataPreferred()) {
            final String jwt = restClient.get()
                    .uri(issuerOpenIdCredentialIssuer)
                    .header(HttpHeaders.ACCEPT, "application/jwt")
                    .retrieve()
                    .body(String.class);

            final JsonNode payload = JwtSupport.decodePayloadToJsonNode(jwt);
            final JsonObject metadata = new Gson().fromJson(payload.toString(), JsonObject.class);

            return new IssuerMetadata(metadata);
        }

        final Map rawMetadata = restClient.get()
                .uri(issuerOpenIdCredentialIssuer)
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .retrieve()
                .body(Map.class);

        JsonObject metadata = new Gson().toJsonTree(rawMetadata).getAsJsonObject();

        return new IssuerMetadata(metadata);
    }

    public OAuthToken collectToken(WalletEntry walletEntry) {
        var tokenUri = issuerContext.getContextualizedUri(walletEntry.getIssuerTokenUri());
        var preAuthorizedCode = walletEntry.getPreAuthorizedCode();

        URI target = UriComponentsBuilder.fromUri(tokenUri)
                .queryParam("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
                .queryParam("pre-authorized_code", preAuthorizedCode)
                .build()
                .toUri();

        return restClient.post()
                .uri(target)
                .retrieve()
                .body(OAuthToken.class);
    }

    public ResponseEntity<NonceResponse> getNonce(WalletEntry walletEntry) {
        final URI cnonceURI = issuerContext.getContextualizedUri(walletEntry.getIssuerMetadata().getNonceEndpointURI());
        final ResponseEntity<NonceResponse> response = restClient.post()
                .uri(cnonceURI)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .retrieve()
                .toEntity(NonceResponse.class);
        return response;
    }

    public String getCNonce(WalletEntry walletEntry) {
        final ResponseEntity<NonceResponse> response = getNonce(walletEntry);
        return response.getBody().getcNonce();
    }

    public String getVerifiableCredentialFromIssuerID2(WalletEntry walletEntry) {
        CredentialResponse credentialResponse = postCredentialRequest(SwiyuApiVersionConfig.ID2, walletEntry);

        assertThat(credentialResponse.getBody().get("format").getAsString()).isEqualTo(VC_SD_JWT);
        assertThat(credentialResponse.getBody().get("credential")).isNotNull();

        return credentialResponse.getBody().get("credential").getAsString();
    }

    public List<String> getVerifiableCredentialFromIssuerV1(WalletBatchEntry batchEntry) {
        CredentialResponse credentialResponse = postCredentialRequest(SwiyuApiVersionConfig.V1, batchEntry);

        assertThat(credentialResponse.getBody()).isNotNull();
        var credentialsElement = credentialResponse.getBody().get("credentials");
        assertThat(credentialsElement).isNotNull();
        assertThat(credentialsElement.isJsonArray()).isTrue();

        var credentialsArray = credentialsElement.getAsJsonArray();
        assertThat(credentialsArray.size()).isEqualTo(batchEntry.getProofs().size());

        List<String> issued = new ArrayList<>();
        for (JsonElement elem : credentialsArray) {
            String jwt = elem.getAsJsonObject().get("credential").getAsString();
            issued.add(jwt);
        }

        return issued;
    }

    private CredentialResponse postDeferredCredentialRequest(final SwiyuApiVersionConfig apiVersion, final WalletEntry walletEntry) {
        if (apiVersion == SwiyuApiVersionConfig.V1) {
            return postDeferredCredentialRequestV1((WalletBatchEntry) walletEntry);
        }
        return postDeferredCredentialRequestID2(walletEntry);
    }

    private CredentialResponse postDeferredCredentialRequestID2(final WalletEntry walletEntry) {
        if (walletEntry.getTransactionId() == null) {
            throw new IllegalStateException("Transaction ID is not set in wallet entry.");
        }

        var deferredCredentialUri = walletEntry.getIssuerDeferredCredentialUri();
        var token = walletEntry.getToken();
        var request = new DeferredCredentialEndpointRequest();
        request.setTransactionId(walletEntry.getTransactionId());

        String requestPayload = null;
        try {
            requestPayload = new ObjectMapper().writeValueAsString(request);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        // Encrypt the payload if encryption is preferred
        final String finalPayload = useEncryption
                ? encryptCredentialRequest(walletEntry, requestPayload)
                : requestPayload;

        String bearerToken = token.getAccessToken();

        ResponseEntity<String> response = restClient.post()
                .uri(issuerContext.getContextualizedUri(deferredCredentialUri))
                .header(HttpHeaders.CONTENT_TYPE, useEncryption ? "application/jwt" : MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + bearerToken)
                .header("SWIYU-API-Version", SwiyuApiVersionConfig.ID2.getValue())
                .body(finalPayload)
                .retrieve()
                .toEntity(String.class);

        int responseStatusCode = response.getStatusCode().value();
        String rawResponse = response.getBody();
        String responseBody = rawResponse;

        assertThat(responseStatusCode)
                .withFailMessage("POST issuer deferred credential request failed: url [%s], response code [%d] and response body [%s], request body: [%s]"
                        .formatted(deferredCredentialUri, responseStatusCode, responseBody, requestPayload))
                .isIn(List.of(200, 202));

        if (useEncryption) {
            JWESupport.assertIsJWE(responseBody);
            responseBody = JWESupport.decryptJWE(walletEntry.getEphemeralEncryptionKey(), responseBody);
        }

        final JsonObject credentialResponse = JsonParser.parseString(responseBody).getAsJsonObject();

        if (credentialResponse.has("credential")) {
            walletEntry.setIssuerSdJwt(credentialResponse.get("credential").getAsString());
        }

        return new CredentialResponse(responseStatusCode, credentialResponse, rawResponse);
    }

    private CredentialResponse postDeferredCredentialRequestV1(final WalletBatchEntry walletEntry) {
        if (walletEntry.getTransactionId() == null) {
            throw new IllegalStateException("Transaction ID is not set in wallet entry.");
        }

        var deferredCredentialUri = walletEntry.getIssuerDeferredCredentialUri();
        var token = walletEntry.getToken();
        var request = new DeferredCredentialEndpointRequest();
        request.setTransactionId(walletEntry.getTransactionId());

        String requestPayload;
        try {
            requestPayload = new ObjectMapper().writeValueAsString(request);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        final String finalPayload = useEncryption
                ? encryptCredentialRequest(walletEntry, requestPayload)
                : requestPayload;

        String bearerToken = token.getAccessToken();

        String doPProofForCredentialRequest = null;
        if (token.getTokenType() != null && token.getTokenType().equals("DPoP")) {
            doPProofForCredentialRequest = createDoPProofForCredentialRequest(walletEntry, deferredCredentialUri);
        }

        var requestBuilder = restClient.post()
                .uri(issuerContext.getContextualizedUri(deferredCredentialUri))
                .header(HttpHeaders.CONTENT_TYPE, useEncryption ? "application/jwt" : MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + bearerToken)
                .header("SWIYU-API-Version", SwiyuApiVersionConfig.V1.getValue());

        if (doPProofForCredentialRequest != null) {
            requestBuilder = requestBuilder.header("DPoP", doPProofForCredentialRequest);
        }

        final ResponseEntity<String> response = requestBuilder
                .body(finalPayload)
                .retrieve()
                .toEntity(String.class);

        int responseCode = response.getStatusCode().value();
        String rawResponse = response.getBody();
        String responseBody = rawResponse;
        assertThat(responseCode)
                .withFailMessage("POST issuer deferred credential request failed: url [%s], code [%d], body [%s], encryption=%s"
                        .formatted(deferredCredentialUri, responseCode, responseBody, useEncryption))
                .isIn(List.of(200, 202));

        if (useEncryption) {
            JWESupport.assertIsJWE(responseBody);
            responseBody = JWESupport.decryptJWE(walletEntry.getEphemeralEncryptionKey(), responseBody);
        }

        final JsonObject credentialResponse = JsonParser.parseString(responseBody).getAsJsonObject();

        if (credentialResponse.has("credentials")) {
            final JsonArray credentials = credentialResponse.getAsJsonArray("credentials");
            credentials.forEach(c -> {
                final String credential = c.getAsJsonObject().get("credential").getAsString();
                walletEntry.addIssuedCredential(credential);
            });
        }

        return new CredentialResponse(responseCode, credentialResponse, rawResponse);
    }

    private String encryptCredentialRequest(WalletEntry walletEntry, String requestJson) {
        try {
            var metadata = walletEntry.getIssuerMetadata();
            var requestEncryptionMetadata = metadata.getCredentialRequestEncryption();

            Object jwksObject = requestEncryptionMetadata.getJwks();
            Map<String, Object> issuerKeyMap;

            if (jwksObject instanceof List<?> jwksList && !jwksList.isEmpty()) {
                issuerKeyMap = (Map<String, Object>) jwksList.get(0);
            } else if (jwksObject instanceof Map<?, ?> jwksMap && jwksMap.containsKey("keys")) {
                var keys = (List<?>) jwksMap.get("keys");
                issuerKeyMap = (Map<String, Object>) keys.get(0);
            } else if (jwksObject instanceof Map<?, ?> singleKey) {
                issuerKeyMap = (Map<String, Object>) singleKey;
            } else {
                throw new IllegalStateException("Unexpected JWKS format in issuer metadata: " + jwksObject);
            }

            var issuerKey = JWK.parse(issuerKeyMap);

            if (walletEntry.getEphemeralEncryptionKey() == null) {
                walletEntry.generateEphemeralEncryptionKey();
            }

            var header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM)
                    .contentType("JWT")
                    .compressionAlgorithm(CompressionAlgorithm.DEF)
                    .keyID(issuerKey.getKeyID())
                    .build();

            var jweObject = new JWEObject(header, new Payload(requestJson));
            jweObject.encrypt(new ECDHEncrypter(issuerKey.toECKey()));

            return jweObject.serialize();

        } catch (Exception e) {
            throw new RuntimeException("Error during encryption", e);
        }
    }

    public CredentialResponse getCredentialFromTransactionId(final SwiyuApiVersionConfig apiVersion, WalletEntry walletEntry) {
        return postDeferredCredentialRequest(apiVersion, walletEntry);
    }

    public CredentialResponse getCredentialFromTransactionId(WalletEntry walletEntry) {
        return postDeferredCredentialRequest(SwiyuApiVersionConfig.ID2, walletEntry);
    }

    public CredentialResponse getCredentialFromTransactionId(WalletBatchEntry walletBatchEntry) {
        return postDeferredCredentialRequest(SwiyuApiVersionConfig.V1, walletBatchEntry);
    }

    public VerificationRequestObject getVerificationDetails(String verificationDeeplink) {
        var query = URI.create(verificationDeeplink).getQuery();
        String[] pairs = query.split("&");

        var verificationUrl =
                verifierContext.getContextualizedUri(
                        PathSupport.toUri(pairs[1].split("=")[1])
                );

        ResponseEntity<String> response = restClient.get()
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
            final ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            final RequestObject requestObject =
                    mapper.readValue(body, RequestObject.class);
            return new VerificationRequestObject.Unsigned(requestObject);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse unsigned request object", e);
        }
    }

    // @TODO Remove duplication with bellow method
    public RequestObject getVerificationDetailsUnsigned(String verificationDeeplink) {
        VerificationRequestObject request = getVerificationDetails(verificationDeeplink);
        return ((VerificationRequestObject.Unsigned) request).requestObject();
    }

    public RequestObject getVerificationDetailsUnsigned(URI verificationDeeplink) {
        return getVerificationDetailsUnsigned(verificationDeeplink.toString());
    }

    public String getVerificationDetailSigned(String verificationDeeplink) {
        VerificationRequestObject request = getVerificationDetails(verificationDeeplink);
        return ((VerificationRequestObject.Signed) request).jwt();
    }

    public void respondToVerification(final SwiyuApiVersionConfig apiVersion, RequestObject requestObject, String token) {
        if (apiVersion == SwiyuApiVersionConfig.V1) {
            respondToVerificationV1(requestObject, token);
            return;
        }
        respondToVerificationID2(requestObject, token);
    }

    public void respondToVerificationID2(RequestObject requestObject, String token) {
        final boolean isEncrypted = requestObject.getResponseMode() == RequestObject.ResponseModeEnum.POST_JWT;

        final String submission = getPresentationSubmissionPayload();
        final MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();

        if (isEncrypted) {
            final JsonWebKey jsonWebKey = requestObject.getClientMetadata().getJwks().getKeys().getFirst();
            jsonWebKey.setAlg("ECDH-ES");
            jsonWebKey.setUse("enc");
            final String encAlg = requestObject.getClientMetadata().getEncryptedResponseEncValuesSupported().getFirst();

            final ECKey verifierPublicKey = JWESupport.toECKey(jsonWebKey);
            final EncryptionMethod encryptionMethod = EncryptionMethod.parse(encAlg);

            final JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.parse(jsonWebKey.getAlg()), encryptionMethod)
                    .contentType("JWT")
                    .keyID(verifierPublicKey.getKeyID())
                    .build();

            final Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("vp_token", token);
            payload.put("presentation_submission", submission);

            final JWEObject jweObject = new JWEObject(jweHeader, new Payload(payload));
            try {
                jweObject.encrypt(new ECDHEncrypter(verifierPublicKey.toECPublicKey()));
            } catch (JOSEException e) {
                throw new RuntimeException("Failed to encrypt VP token response (ID2)", e);
            }

            formData.add("response", jweObject.serialize());
        } else {
            formData.add("presentation_submission", submission);
            formData.add("vp_token", token);
        }

        final var response = restClient.post()
                .uri(verifierContext.getContextualizedUri(PathSupport.toUri(requestObject.getResponseUri())))
                .headers(headers -> {
                    headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
                    headers.add("SWIYU-API-Version", SwiyuApiVersionConfig.ID2.getValue());
                })
                .body(formData)
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
    }

    public void respondToVerificationV1(final RequestObject requestObject, final String token) {
        final boolean isEncrypted = requestObject.getResponseMode() == RequestObject.ResponseModeEnum.POST_JWT;

        final String tokenId = requestObject.getDcqlQuery().getCredentials().getFirst().getId();
        final Map<String, List<String>> vpToken = Map.of(tokenId, List.of(token));

        final MultiValueMap<String, Object> formData = new LinkedMultiValueMap<>();

        if (isEncrypted) {
            final JsonWebKey jsonWebKey = requestObject.getClientMetadata().getJwks().getKeys().getFirst();
            jsonWebKey.setAlg("ECDH-ES");
            jsonWebKey.setUse("enc");
            final String encAlg = requestObject.getClientMetadata().getEncryptedResponseEncValuesSupported().getFirst();

            final ECKey verifierPublicKey = JWESupport.toECKey(jsonWebKey);
            final EncryptionMethod encryptionMethod = EncryptionMethod.parse(encAlg);

            final JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.parse(jsonWebKey.getAlg()), encryptionMethod)
                    .contentType("JWT")
                    .keyID(verifierPublicKey.getKeyID())
                    .build();

            final JWEObject jweObject = new JWEObject(jweHeader, new Payload(Map.of("vp_token", vpToken)));
            try {
                jweObject.encrypt(new ECDHEncrypter(verifierPublicKey.toECPublicKey()));
            } catch (JOSEException e) {
                throw new RuntimeException("Failed to encrypt VP token response (V1)", e);
            }

            formData.add("response", jweObject.serialize());
        } else {
            formData.add("vp_token", new Gson().toJson(vpToken));
        }

        final ResponseEntity<String> response = restClient.post()
                .uri(verifierContext.getContextualizedUri(PathSupport.toUri(requestObject.getResponseUri())))
                .headers(headers -> {
                    headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
                    headers.add("SWIYU-API-Version", SwiyuApiVersionConfig.V1.getValue());
                })
                .body(formData)
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
    }

    public WalletEntry collectOffer(final SwiyuApiVersionConfig apiVersion, final URI offerDeepLink) {
        if (apiVersion == SwiyuApiVersionConfig.V1) {
            return collectOfferV1(offerDeepLink);
        }
        return collectOfferID2(offerDeepLink);
    }

    public WalletEntry collectOfferID2(URI offerDeepLink) {
        final WalletEntry walletEntry = createWalletEntry();
        walletEntry.receiveDeepLinkAndValidateIt(issuerContext.getContextualizedUri(offerDeepLink));
        walletEntry.setIssuerWellKnownConfiguration(getIssuerWellKnownConfiguration(walletEntry));
        walletEntry.setToken(collectToken(walletEntry));
        walletEntry.setIssuerMetadata(getIssuerWellKnownMetadata(walletEntry));
        walletEntry.setCredentialConfigurationSupported();
        walletEntry.setIssuerSdJwt(getVerifiableCredentialFromIssuerID2(walletEntry));
        return walletEntry;
    }

    public WalletBatchEntry collectOfferV1(URI offerDeepLink) {
        var entry = createWalletBatchEntry();
        entry.receiveDeepLinkAndValidateIt(issuerContext.getContextualizedUri(offerDeepLink));
        entry.setIssuerWellKnownConfiguration(getIssuerWellKnownConfiguration(entry));
        entry.setToken(collectToken(entry));
        entry.setIssuerMetadata(getIssuerWellKnownMetadata(entry));
        entry.setCredentialConfigurationSupported();

        entry.generateHolderKeys();
        entry.createProofs();

        getVerifiableCredentialFromIssuerV1(entry);

        return entry;
    }

    private CredentialResponse postCredentialRequest(final SwiyuApiVersionConfig apiVersion, final WalletEntry walletEntry) {
        if (apiVersion == SwiyuApiVersionConfig.V1) {
            return postCredentialRequestV1((WalletBatchEntry) walletEntry);
        }
        return postCredentialRequestID2(walletEntry);
    }

    private CredentialResponse postCredentialRequestID2(final WalletEntry walletEntry) {
        final URI credentialUri = walletEntry.getIssuerCredentialUri();
        final OAuthToken token = walletEntry.getToken();
        final String bearerToken = token.getAccessToken();

        var credentialConfigurationSupported = walletEntry.getCredentialConfigurationSupported();
        var request = new CredentialEndpointRequest();
        request.setFormat(VC_SD_JWT);

        if (credentialConfigurationSupported.has("proof_types_supported")) {
            var proof = walletEntry.createProof().toJwt();
            Map<String, Object> proofMap = Map.of("proof_type", "jwt", "jwt", proof);
            request.setProof(proofMap);
        }

        if (useEncryption) {
            walletEntry.generateEphemeralEncryptionKey();

            var metadata = walletEntry.getIssuerMetadata();
            var encryptionMetadata = metadata.getCredentialResponseEncryption();
            var responseEncryption = new CredentialResponseEncryption()
                    .alg(encryptionMetadata.getAlgValuesSupported().getFirst())
                    .enc(encryptionMetadata.getEncValuesSupported().getFirst())
                    .jwk(walletEntry.getEphemeralEncryptionKey().toPublicJWK().toJSONObject());

            request.setCredentialResponseEncryption(responseEncryption);
        }

        String requestPayload;
        try {
            requestPayload = new ObjectMapper().writeValueAsString(request);
        } catch (JsonProcessingException ex) {
            throw new RuntimeException("Cannot serialize payload credential", ex);
        }

        final String finalPayload = useEncryption
                ? encryptCredentialRequest(walletEntry, requestPayload)
                : requestPayload;

        ResponseEntity<String> response = restClient.post()
                .uri(issuerContext.getContextualizedUri(credentialUri))
                .header(HttpHeaders.CONTENT_TYPE, useEncryption ? "application/jwt" : MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + bearerToken)
                .header("SWIYU-API-Version", SwiyuApiVersionConfig.ID2.getValue())
                .body(finalPayload)
                .retrieve()
                .toEntity(String.class);

        int responseStatusCode = response.getStatusCode().value();
        String rawResponse = response.getBody();
        String bodyAsString = rawResponse;

        assertThat(responseStatusCode)
                .withFailMessage("POST issuer credential request failed: url [%s], code [%d], body [%s], encryption=%s"
                        .formatted(credentialUri, responseStatusCode, bodyAsString, useEncryption))
                .isIn(List.of(200, 202));

        if (useEncryption) {
            try {
                JWESupport.assertIsJWE(bodyAsString);
                bodyAsString = JWESupport.decryptJWE(walletEntry.getEphemeralEncryptionKey(), bodyAsString);
            } catch (Exception e) {
                throw new RuntimeException("Error decrypting credential response", e);
            }
        }

        final JsonObject credentialResponse = JsonParser.parseString(bodyAsString).getAsJsonObject();

        if (credentialResponse.has("credential")) {
            walletEntry.setIssuerSdJwt(credentialResponse.get("credential").getAsString());
        }

        return new CredentialResponse(responseStatusCode, credentialResponse, rawResponse);
    }

    private CredentialResponse postCredentialRequestV1(final WalletBatchEntry walletEntry) {
        final URI credentialUri = walletEntry.getIssuerCredentialUri();
        final OAuthToken token = walletEntry.getToken();
        final String bearerToken = token.getAccessToken();

        var proofsDto = new ProofsDto();
        proofsDto.setJwt(walletEntry.getProofsAsJwt());

        var metadata = walletEntry.getIssuerMetadata();
        var requestDto = new CredentialEndpointRequestV2()
                .credentialConfigurationId(walletEntry.getCredentialOffer().getCredentialConfiguraionId())
                .proofs(proofsDto);

        if (useEncryption) {
            walletEntry.generateEphemeralEncryptionKey();

            var encryptionMetadata = metadata.getCredentialResponseEncryption();
            var responseEncryption = new CredentialResponseEncryption()
                    .alg(encryptionMetadata.getAlgValuesSupported().getFirst())
                    .enc(encryptionMetadata.getEncValuesSupported().getFirst())
                    .jwk(walletEntry.getEphemeralEncryptionKey().toPublicJWK().toJSONObject());

            requestDto.credentialResponseEncryption(responseEncryption);
        }

        final String requestPayload;
        try {
            requestPayload = new ObjectMapper().writeValueAsString(requestDto);
        } catch (JsonProcessingException ex) {
            throw new RuntimeException("Failed to serialize credential request payload", ex);
        }

        final String finalPayload = useEncryption
                ? encryptCredentialRequest(walletEntry, requestPayload)
                : requestPayload;

        String doPProofForCredentialRequest = null;
        if (token.getTokenType() != null && token.getTokenType().equals("DPoP")) {
            doPProofForCredentialRequest = createDoPProofForCredentialRequest(walletEntry, credentialUri);
        }

        var requestBuilder = restClient.post()
                .uri(issuerContext.getContextualizedUri(credentialUri))
                .header(HttpHeaders.CONTENT_TYPE, useEncryption ? "application/jwt" : MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + bearerToken)
                .header("SWIYU-API-Version", SwiyuApiVersionConfig.V1.getValue());

        if (doPProofForCredentialRequest != null) {
            requestBuilder = requestBuilder.header("DPoP", doPProofForCredentialRequest);
        }

        final ResponseEntity<String> response = requestBuilder
                .body(finalPayload)
                .retrieve()
                .toEntity(String.class);

        int responseCode = response.getStatusCode().value();
        String rawResponse = response.getBody();
        String responseBody = rawResponse;
        assertThat(responseCode)
                .withFailMessage("POST issuer credential request failed: url [%s], code [%d], body [%s], encryption=%s"
                        .formatted(credentialUri, responseCode, responseBody, useEncryption))
                .isIn(List.of(200, 202));

        if (useEncryption) {
            try {
                JWESupport.assertIsJWE(responseBody);
                responseBody = JWESupport.decryptJWE(walletEntry.getEphemeralEncryptionKey(), responseBody);
            } catch (Exception e) {
                throw new RuntimeException("Error decrypting credential response", e);
            }
        }

        final JsonObject credentialResponse = JsonParser.parseString(responseBody).getAsJsonObject();

        if (credentialResponse.has("credentials")) {

            final JsonArray credentials = credentialResponse.getAsJsonArray("credentials");
            credentials.forEach(c -> {
                final String credential = c.getAsJsonObject().get("credential").getAsString();
                walletEntry.addIssuedCredential(credential);
            });
        }

        return new CredentialResponse(responseCode, credentialResponse, rawResponse);
    }

    public String getDpopNonce(WalletEntry walletEntry) {
        ResponseEntity<NonceResponse> response = getNonce(walletEntry);
        return response.getHeaders().getFirst("dpop-nonce");
    }

    public OAuthToken collectTokenWithDPoP(WalletEntry walletEntry, String doPProof) {
        final URI tokenUri = issuerContext.getContextualizedUri(walletEntry.getIssuerTokenUri());
        final String preAuthorizedCode = walletEntry.getPreAuthorizedCode();

        final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code");
        params.add("pre-authorized_code", preAuthorizedCode);

        final ResponseEntity<OAuthToken> response = restClient.post()
                .uri(tokenUri)
                .header("SWIYU-API-Version", SwiyuApiVersionConfig.V1.getValue())
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .header("DPoP", doPProof)
                .body(params)
                .retrieve()
                .toEntity(OAuthToken.class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        return response.getBody();
    }

    public OAuthToken collectRefreshTokenWithDPoP(WalletEntry walletEntry, String doPProof) {
        final URI tokenUri = issuerContext.getContextualizedUri(walletEntry.getIssuerTokenUri());

        final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "refresh_token");
        params.add("refresh_token", walletEntry.getToken().getRefreshToken());

        final ResponseEntity<OAuthToken> response = restClient.post()
                .uri(tokenUri)
                .header("SWIYU-API-Version", SwiyuApiVersionConfig.V1.getValue())
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .header("DPoP", doPProof)
                .body(params)
                .retrieve()
                .toEntity(OAuthToken.class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        return response.getBody();
    }

    public JsonObject postCredentialRequestWithRefreshToken(WalletBatchEntry walletEntry, final String accessToken, final String dpopProof) {

        final URI credentialUri = issuerContext.getContextualizedUri(walletEntry.getIssuerCredentialUri());

        var proofsDto = new ProofsDto();
        proofsDto.setJwt(walletEntry.getProofsAsJwt());

        var requestDto = new CredentialEndpointRequestV2()
                .credentialConfigurationId(walletEntry.getCredentialOffer().getCredentialConfiguraionId())
                .proofs(proofsDto);

        final String requestPayload;
        try {
            requestPayload = new ObjectMapper().writeValueAsString(requestDto);
        } catch (JsonProcessingException ex) {
            throw new RuntimeException("Cannot serialize credential request payload", ex);
        }

        var builder = restClient.post()
                .uri(credentialUri)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken)
                .header("SWIYU-API-Version", SwiyuApiVersionConfig.V1.getValue());

        if (dpopProof != null) {
            builder = builder.header("DPoP", dpopProof);
        }

        var response = builder
                .body(requestPayload)
                .retrieve()
                .toEntity(String.class);


        int code = response.getStatusCode().value();
        String body = response.getBody();

        assertThat(code)
                .withFailMessage("Credential request via refresh failed: code=%s body=%s", code, body)
                .isIn(200, 202);

        final JsonObject credentialResponse = JsonParser.parseString(body).getAsJsonObject();

        if (credentialResponse.has("credentials")) {
            walletEntry.getIssuedCredentials().clear();
            JsonArray arr = credentialResponse.getAsJsonArray("credentials");
            arr.forEach(e ->
                    walletEntry.addIssuedCredential(
                            e.getAsJsonObject().get("credential").getAsString()
                    ));
        }

        return credentialResponse;
    }

    public OAuthToken refreshTokenWithDPoP(WalletEntry walletEntry, String doPProof) {
        final URI tokenUri = issuerContext.getContextualizedUri(walletEntry.getIssuerTokenUri());
        final String refreshToken = walletEntry.getToken().getRefreshToken();

        assertThat(refreshToken).isNotNull().isNotEmpty();

        final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "refresh_token");
        params.add("refresh_token", refreshToken);

        final ResponseEntity<OAuthToken> response = restClient.post()
                .uri(tokenUri)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .header("DPoP", doPProof)
                .body(params)
                .retrieve()
                .toEntity(OAuthToken.class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        return response.getBody();
    }

    private String createDoPProofForCredentialRequest(WalletEntry walletEntry, URI credentialUri) {
        try {
            String nonce = getDpopNonce(walletEntry);

            String accessToken = walletEntry.getToken().getAccessToken();

            String uri = credentialUri.toString();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("openid4vci-proof+jwt"))
                    .jwk(walletEntry.getProofPublicJwk())
                    .build();

            String issuerIdentifier = walletEntry.getIssuerMetadata().getIssuerURI();

            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .audience(issuerIdentifier)
                    .claim("htm", "POST")
                    .claim("htu", uri)
                    .issueTime(new Date())
                    .jwtID(UUID.randomUUID().toString())
                    .claim("nonce", nonce);

            if (accessToken != null) {
                claimsBuilder.claim("ath", hashAccessToken(accessToken));
            }

            JWTClaimsSet claims = claimsBuilder.build();

            SignedJWT signedJWT = new SignedJWT(header, claims);
            signedJWT.sign(new ECDSASigner((ECPrivateKey) walletEntry.getKeyPair().getPrivate()));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create DPoP proof for credential request", e);
        }
    }

    private String hashAccessToken(String accessToken) {
        try {
            var digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(accessToken.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    public void postCredentialRequestWithCustomDPoP(WalletBatchEntry batchEntry, String customDpopProof, URI credentialUri) {
        final OAuthToken token = batchEntry.getToken();
        final String bearerToken = token.getAccessToken();
        var proofsDto = new ProofsDto();
        proofsDto.setJwt(batchEntry.getProofsAsJwt());
        var requestDto = new CredentialEndpointRequestV2()
                .credentialConfigurationId(batchEntry.getCredentialOffer().getCredentialConfiguraionId())
                .proofs(proofsDto);

        final String requestPayload;
        try {
            requestPayload = new ObjectMapper().writeValueAsString(requestDto);
        } catch (JsonProcessingException ex) {
            throw new RuntimeException("Failed to serialize credential request payload", ex);
        }

        var requestBuilder = restClient.post()
                .uri(issuerContext.getContextualizedUri(credentialUri))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + bearerToken)
                .header("SWIYU-API-Version", SwiyuApiVersionConfig.V1.getValue());

        if (customDpopProof != null) {
            requestBuilder = requestBuilder.header("DPoP", customDpopProof);
        }

        final ResponseEntity<String> response = requestBuilder
                .body(requestPayload)
                .retrieve()
                .toEntity(String.class);

        int responseCode = response.getStatusCode().value();
        String responseBody = response.getBody();
        assertThat(responseCode)
                .withFailMessage("POST issuer credential request failed: url [%s], code [%d], body [%s]"
                        .formatted(credentialUri, responseCode, responseBody))
                .isIn(List.of(200, 202));
    }

}
