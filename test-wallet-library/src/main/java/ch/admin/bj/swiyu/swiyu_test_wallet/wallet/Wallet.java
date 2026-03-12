package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.gen.issuer.model.*;
import ch.admin.bj.swiyu.gen.verifier.model.JsonWebKey;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.jweutil.JweUtil;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.exceptions.WalletEncryptionException;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_response.CredentialResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequestObject;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
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
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.util.*;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.JsonConverter.toJsonNode;
import static org.assertj.core.api.Assertions.assertThat;

@Getter
@Setter
public class Wallet {

    public static final String BEARER_PREFIX = "Bearer ";
    public static final String VC_SD_JWT = "vc+sd-jwt";
    public static final String APPLICATION_JWT = "application/jwt";
    public static final String GRANT_TYPE = "grant_type";
    public static final String CREDENTIAL = "credential";
    public static final String CREDENTIALS = "credentials";
    public static final String SWIYU_API_VERSION_HEADER = "SWIYU-API-Version";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String VP_TOKEN = "vp_token";

    private final RestClient restClient;
    private final ServiceLocationContext issuerContext;
    private final ServiceLocationContext verifierContext;

    private boolean useEncryption = false;
    private boolean useDPoP = false;
    private boolean signedMetadataPreferred = false;
    private KeyPair dpopKeyPair;
    private ECKey dpopPublicKey;

    public Wallet(RestClient restClient, ServiceLocationContext issuerContext, ServiceLocationContext verifierContext) {
        this.restClient = restClient;
        this.issuerContext = issuerContext;
        this.verifierContext = verifierContext;
        this.generateDPoPKey();
    }

    public Wallet(RestClient restClient, ServiceLocationContext issuerContext, ServiceLocationContext verifierContext, boolean useEncryption) {
        this(restClient, issuerContext, verifierContext);
        this.useEncryption = useEncryption;
        this.generateDPoPKey();
    }

    public WalletBatchEntry createWalletBatchEntry() {
        return new WalletBatchEntry(this);
    }

    public void generateDPoPKey() {
        dpopKeyPair = ECCryptoSupport.generateECKeyPair();
        dpopPublicKey = new ECKey.Builder(
                Curve.P_256,
                (java.security.interfaces.ECPublicKey) dpopKeyPair.getPublic())
                .keyUse(KeyUse.SIGNATURE)
                .keyID("holder-dpop-key-" + UUID.randomUUID())
                .build();
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

    public WalletBatchEntry collectTransactionIdFromDeferredOffer(URI issuerDeepLink) {
        var walletBatchEntry = createWalletBatchEntry();

        walletBatchEntry.receiveDeepLinkAndValidateIt(issuerContext.getContextualizedUri(issuerDeepLink));
        walletBatchEntry.setIssuerWellKnownConfiguration(getIssuerWellKnownConfiguration(walletBatchEntry));
        walletBatchEntry.setIssuerMetadata(getIssuerWellKnownMetadata(walletBatchEntry));

        if (this.useDPoP) {
            final String nonceInitial = collectDPoPNonce(walletBatchEntry);
            final String tokenDPoP = DPoPSupport.createDpopProofForToken(
                    walletBatchEntry.getIssuerTokenUri().toString(), nonceInitial, dpopKeyPair, dpopPublicKey);
            walletBatchEntry.setToken(collectTokenWithDPoP(walletBatchEntry, tokenDPoP));
        } else {
            walletBatchEntry.setToken(collectToken(walletBatchEntry));
        }
        walletBatchEntry.setCNonce(collectCNonce(walletBatchEntry));

        walletBatchEntry.setCredentialConfigurationSupported();

        walletBatchEntry.generateHolderKeys();
        walletBatchEntry.createProofs();

        CredentialResponse deferredCredentialTransactionIdResponse = postCredentialRequest(walletBatchEntry);

        assertThat(deferredCredentialTransactionIdResponse)
                .isNotNull();

        var transactionIdNode = deferredCredentialTransactionIdResponse.getBody().get("transaction_id");
        assertThat(transactionIdNode).isNotNull();
        var transactionId = transactionIdNode.getAsString();
        assertThat(transactionId).isNotNull();

        walletBatchEntry.setTransactionId(UUID.fromString(transactionId));
        return walletBatchEntry;
    }

    public OAuthAuthorizationServerMetadata getIssuerWellKnownConfiguration(WalletEntry walletEntry) {
        final URI issuerUri = issuerContext.getContextualizedUri(walletEntry.getIssuerUri());
        final URI issuerOpenIdConfiguration = UriComponentsBuilder
                .fromUri(issuerUri)
                .pathSegment(".well-known", "openid-configuration")
                .build()
                .toUri();

        final JsonNode rawMetadata;

        if (this.isSignedMetadataPreferred()) {
            final String jwt = restClient.get()
                    .uri(issuerOpenIdConfiguration)
                    .header(HttpHeaders.ACCEPT, APPLICATION_JWT)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .retrieve()
                    .body(String.class);

            rawMetadata = JwtSupport.decodePayloadToJsonNode(jwt);

        } else {
            rawMetadata = restClient.get()
                    .uri(issuerOpenIdConfiguration)
                    .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .retrieve()
                    .body(JsonNode.class);
        }

        walletEntry.setIssuerWellKnownConfigurationRaw(rawMetadata);

        try {
            ObjectMapper mapper = new ObjectMapper()
                    .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

            return mapper.treeToValue(rawMetadata, OAuthAuthorizationServerMetadata.class);

        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse issuer well-known configuration", e);
        }
    }

    public IssuerMetadata getIssuerWellKnownMetadata(WalletEntry walletEntry) {
        final URI issuerUri = issuerContext.getContextualizedUri(walletEntry.getIssuerUri());
        final URI issuerOpenIdCredentialIssuer = UriComponentsBuilder
                .fromUri(issuerUri)
                .pathSegment(".well-known", "openid-credential-issuer")
                .build()
                .toUri();

        final JsonNode rawMetadata;

        if (this.isSignedMetadataPreferred()) {
            final String jwt = restClient.get()
                    .uri(issuerOpenIdCredentialIssuer)
                    .header(HttpHeaders.ACCEPT, APPLICATION_JWT)
                    .retrieve()
                    .body(String.class);

            rawMetadata = JwtSupport.decodePayloadToJsonNode(jwt);

        } else {
            rawMetadata = restClient.get()
                    .uri(issuerOpenIdCredentialIssuer)
                    .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                    .retrieve()
                    .body(JsonNode.class);
        }

        walletEntry.setIssuerMetadataRaw(rawMetadata);

        try {
            final ObjectMapper mapper = new ObjectMapper()
                    .registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
                    .disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                    .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

            return mapper.treeToValue(rawMetadata, IssuerMetadata.class);

        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse issuer metadata", e);
        }
    }

    public OAuthToken collectToken(WalletEntry walletEntry) {
        final URI tokenUri = issuerContext.getContextualizedUri(walletEntry.getIssuerTokenUri());
        final String preAuthorizedCode = walletEntry.getPreAuthorizedCode();

        final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(GRANT_TYPE, "urn:ietf:params:oauth:grant-type:pre-authorized_code");
        params.add("pre-authorized_code", preAuthorizedCode);

        return restClient.post()
                .uri(tokenUri)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .body(params)
                .retrieve()
                .body(OAuthToken.class);
    }

    public ResponseEntity<NonceResponse> collectNonce(WalletEntry walletEntry) {
        String nonceEndpointStr = walletEntry.getIssuerMetadata().getNonceEndpoint();
        if (nonceEndpointStr == null) {
            throw new IllegalStateException("nonce_endpoint not available in issuer metadata");
        }
        final URI cnonceURI = issuerContext.getContextualizedUri(URI.create(nonceEndpointStr));
        return restClient.post()
                .uri(cnonceURI)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .retrieve()
                .toEntity(NonceResponse.class);
    }

    public String collectCNonce(WalletEntry walletEntry) {
        final ResponseEntity<NonceResponse> response = collectNonce(walletEntry);
        final NonceResponse body = response.getBody();
        if (body == null) {
            throw new IllegalStateException("NonceResponse body is null");
        }
        return body.getcNonce();
    }

    public List<String> getVerifiableCredentialFromIssuer(final WalletBatchEntry batchEntry) {
        CredentialResponse credentialResponse = postCredentialRequest(batchEntry);

        assertThat(credentialResponse.getBody()).isNotNull();
        var credentialsElement = credentialResponse.getBody().get(CREDENTIALS);
        assertThat(credentialsElement).isNotNull();
        assertThat(credentialsElement.isJsonArray()).isTrue();

        var credentialsArray = credentialsElement.getAsJsonArray();
        assertThat(credentialsArray.size()).isEqualTo(batchEntry.getProofs().size());

        List<String> issued = new ArrayList<>();
        for (JsonElement elem : credentialsArray) {
            String jwt = elem.getAsJsonObject().get(CREDENTIAL).getAsString();
            issued.add(jwt);
        }

        return issued;
    }

    private CredentialResponse postDeferredCredentialRequest(final WalletBatchEntry walletEntry) {
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
            throw new IllegalStateException("Cannot serialize deferred credential request", e);
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
                .header(HttpHeaders.CONTENT_TYPE, useEncryption ? APPLICATION_JWT : MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + bearerToken);

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
            responseBody = JweUtil.decrypt(responseBody, walletEntry.getEphemeralEncryptionKey());
        }

        final JsonObject credentialResponse = JsonParser.parseString(responseBody).getAsJsonObject();

        if (credentialResponse.has(CREDENTIALS)) {
            walletEntry.clearIssuedCredentials();
            final JsonArray credentials = credentialResponse.getAsJsonArray(CREDENTIALS);
            credentials.forEach(c -> {
                final String credential = c.getAsJsonObject().get(CREDENTIAL).getAsString();
                walletEntry.addIssuedCredential(credential);
            });
        }

        final CredentialResponse completeCredentialResponse = new CredentialResponse(responseCode, credentialResponse, rawResponse);

        walletEntry.setCredentialResponse(completeCredentialResponse);

        return completeCredentialResponse;
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
            throw new IllegalStateException("Error during encryption", e);
        }
    }

    public CredentialResponse getCredentialFromTransactionId(WalletBatchEntry walletBatchEntry) {
        return postDeferredCredentialRequest(walletBatchEntry);
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
            throw new IllegalStateException("Failed to parse unsigned request object", e);
        }
    }

    public RequestObject getVerificationDetailsUnsigned(String verificationDeeplink) {
        VerificationRequestObject request = getVerificationDetails(verificationDeeplink);
        return ((VerificationRequestObject.Unsigned) request).requestObject();
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
        final String submission = getPresentationSubmissionPayload();
        final MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();

        if (useEncryption) {
            final Map<String, Object> payload = new LinkedHashMap<>();
            payload.put(VP_TOKEN, token);
            payload.put("presentation_submission", submission);
            formData.add("response", buildEncryptedResponse(requestObject, payload));
        } else {
            formData.add("presentation_submission", submission);
            formData.add(VP_TOKEN, token);
        }

        final var response = restClient.post()
                .uri(verifierContext.getContextualizedUri(PathSupport.toUri(requestObject.getResponseUri())))
                .headers(headers -> {
                    headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
                    headers.add(SWIYU_API_VERSION_HEADER, SwiyuApiVersionConfig.ID2.getValue());
                })
                .body(formData)
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
    }

    public void respondToVerificationV1(final RequestObject requestObject, final String token) {
        final String tokenId = requestObject.getDcqlQuery().getCredentials().getFirst().getId();
        final Map<String, Object> vpToken = Map.of(tokenId, List.of(token));

        final MultiValueMap<String, Object> formData = new LinkedMultiValueMap<>();

        if (useEncryption) {
            formData.add("response", buildEncryptedResponse(requestObject, vpToken));
        } else {
            formData.add(VP_TOKEN, new Gson().toJson(vpToken));
        }

        final ResponseEntity<String> response = restClient.post()
                .uri(verifierContext.getContextualizedUri(PathSupport.toUri(requestObject.getResponseUri())))
                .headers(headers -> {
                    headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
                    headers.add(SWIYU_API_VERSION_HEADER, SwiyuApiVersionConfig.V1.getValue());
                })
                .body(formData)
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
    }

    public CredentialResponse renewedCredentials(WalletBatchEntry batchEntry) {
        final String nonce = collectCNonce(batchEntry);
        batchEntry.generateHolderKeys();
        batchEntry.createProofs(nonce);

        return postCredentialRequest(batchEntry);
    }

    public WalletBatchEntry collectOffer(final URI offerDeepLink) {
        return collectOffer(offerDeepLink, null);
    }

    public WalletBatchEntry collectOffer(final URI offerDeepLink, final Integer count) {
        final WalletBatchEntry entry = createWalletBatchEntry();
        entry.receiveDeepLinkAndValidateIt(issuerContext.getContextualizedUri(offerDeepLink));
        entry.setIssuerWellKnownConfiguration(getIssuerWellKnownConfiguration(entry));
        entry.setIssuerMetadata(getIssuerWellKnownMetadata(entry));
        entry.setCredentialConfigurationSupported();

        if (this.useDPoP) {
            final String nonceInitial = collectDPoPNonce(entry);
            final String tokenDPoP = DPoPSupport.createDpopProofForToken(
                    entry.getIssuerTokenUri().toString(), nonceInitial, dpopKeyPair, dpopPublicKey);
            entry.setToken(collectTokenWithDPoP(entry, tokenDPoP));
        } else {
            entry.setToken(collectToken(entry));
        }

        entry.setCNonce(collectCNonce(entry));

        int effectiveCount = (count != null)
                ? count
                : entry.getIssuerMetadata().getBatchCredentialIssuance().getBatchSize();
        entry.generateHolderKeys(effectiveCount);
        entry.createProofs();

        getVerifiableCredentialFromIssuer(entry);

        return entry;
    }

    public CredentialResponse postCredentialRequest(final WalletBatchEntry walletEntry) {
        final URI credentialUri = walletEntry.getIssuerCredentialUri();
        final OAuthToken token = walletEntry.getToken();
        final String bearerToken = token.getAccessToken();

        var proofsDto = new ProofsDto();
        proofsDto.setJwt(walletEntry.getProofsAsJwt());

        var metadata = walletEntry.getIssuerMetadata();
        var requestDto = new CredentialEndpointRequestV2()
                .credentialConfigurationId(walletEntry.getCredentialOffer().getCredentialConfiguraionId())
                .proofs(proofsDto);

        if (this.useEncryption) {
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
            throw new IllegalStateException("Failed to serialize credential request payload", ex);
        }

        final String finalPayload = useEncryption
                ? encryptCredentialRequest(walletEntry, requestPayload)
                : requestPayload;

        var requestBuilder = restClient.post()
                .uri(issuerContext.getContextualizedUri(credentialUri))
                .header(HttpHeaders.CONTENT_TYPE, useEncryption ? APPLICATION_JWT : MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + bearerToken);

        if (this.useDPoP) {
            final String dPoP = generateDpopForCredentialEndpoint(walletEntry);
            requestBuilder = requestBuilder.header("DPoP", dPoP);
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
                responseBody = JweUtil.decrypt(responseBody, walletEntry.getEphemeralEncryptionKey());
            } catch (Exception e) {
                throw new IllegalStateException("Error decrypting credential response", e);
            }
        }

        final JsonObject credentialResponse = JsonParser.parseString(responseBody).getAsJsonObject();

        if (credentialResponse.has(CREDENTIALS)) {

            final JsonArray credentials = credentialResponse.getAsJsonArray(CREDENTIALS);
            credentials.forEach(c -> {
                final String credential = c.getAsJsonObject().get(CREDENTIAL).getAsString();
                walletEntry.addIssuedCredential(credential);
            });
        }

        final CredentialResponse completeCredentialResponse = new CredentialResponse(responseCode, credentialResponse, rawResponse);

        walletEntry.setCredentialResponse(completeCredentialResponse);

        return completeCredentialResponse;
    }

    public String collectDPoPNonce(WalletEntry walletEntry) {
        ResponseEntity<NonceResponse> response = collectNonce(walletEntry);
        return response.getHeaders().getFirst("dpop-nonce");
    }

    public OAuthToken collectTokenWithDPoP(WalletEntry walletEntry, String doPProof) {
        final URI tokenUri = issuerContext.getContextualizedUri(walletEntry.getIssuerTokenUri());
        final String preAuthorizedCode = walletEntry.getPreAuthorizedCode();

        final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(GRANT_TYPE, "urn:ietf:params:oauth:grant-type:pre-authorized_code");
        params.add("pre-authorized_code", preAuthorizedCode);

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

    public OAuthToken collectRefreshTokenWithDPoP(WalletEntry walletEntry, String doPProof) {
        final URI tokenUri = issuerContext.getContextualizedUri(walletEntry.getIssuerTokenUri());

        final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(GRANT_TYPE, REFRESH_TOKEN);
        params.add(REFRESH_TOKEN, walletEntry.getToken().getRefreshToken());

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

    public OAuthToken refreshTokenWithDPoP(WalletEntry walletEntry, String doPProof) {
        final URI tokenUri = issuerContext.getContextualizedUri(walletEntry.getIssuerTokenUri());
        final String refreshToken = walletEntry.getToken().getRefreshToken();

        assertThat(refreshToken).isNotNull().isNotEmpty();

        final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(GRANT_TYPE, REFRESH_TOKEN);
        params.add(REFRESH_TOKEN, refreshToken);

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
            String nonce = collectDPoPNonce(walletEntry);

            String accessToken = walletEntry.getToken().getAccessToken();

            String uri = credentialUri.toString();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("openid4vci-proof+jwt"))
                    .jwk(walletEntry.getProofPublicJwk())
                    .build();

            String issuerIdentifier = walletEntry.getIssuerMetadata().getCredentialIssuer();

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
            throw new IllegalStateException("Failed to create DPoP proof for credential request", e);
        }
    }

    private String hashAccessToken(String accessToken) {
        try {
            var digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(accessToken.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
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
            throw new IllegalStateException("Failed to serialize credential request payload", ex);
        }

        var requestBuilder = restClient.post()
                .uri(issuerContext.getContextualizedUri(credentialUri))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + bearerToken);

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

    private String buildEncryptedResponse(final RequestObject requestObject, final Map<String, Object> payload) {
        try {
            final JsonWebKey jsonWebKey = requestObject.getClientMetadata()
                    .getJwks()
                    .getKeys()
                    .getFirst();
            final ECKey verifierPublicKey = JWESupport.toECKey(jsonWebKey);
            final String vpTokenPayload =
                    new ObjectMapper().writeValueAsString(Map.of(VP_TOKEN, payload));
            return JweUtil.encrypt(vpTokenPayload, verifierPublicKey);
        } catch (Exception e) {
            throw new WalletEncryptionException("Failed to build encrypted VP token response (JWE creation failed)", e);
        }
    }

    public String generateDpopForCredentialEndpoint(final WalletEntry walletEntry) {
        walletEntry.setCNonce(collectDPoPNonce(walletEntry));
        return DPoPSupport.createDpopProofForToken(
                walletEntry.getIssuerCredentialUri().toString(),
                walletEntry.getCNonce(),
                dpopKeyPair,
                dpopPublicKey,
                walletEntry.getToken().getAccessToken()
        );
    }

}
