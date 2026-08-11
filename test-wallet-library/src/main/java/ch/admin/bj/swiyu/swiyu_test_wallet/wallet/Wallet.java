package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.gen.issuer.model.*;
import ch.admin.bj.swiyu.gen.verifier.model.JsonWebKey;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.jweutil.JweUtil;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockAttestationAuthority;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerHandle;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierHandle;
import ch.admin.bj.swiyu.swiyu_test_wallet.exceptions.WalletEncryptionException;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_response.CredentialResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequestObject;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.json.JsonMapper;
import com.google.gson.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.security.KeyPair;
import java.util.*;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.JsonConverter.toJsonNode;
import static org.assertj.core.api.Assertions.assertThat;

@Getter
@Setter
public class Wallet {

    public static final String BEARER_PREFIX = "Bearer ";
    public static final String APPLICATION_JWT = "application/jwt";
    public static final String GRANT_TYPE = "grant_type";
    public static final String CREDENTIAL = "credential";
    public static final String CREDENTIALS = "credentials";
    public static final String TRANSACTION_ID = "transaction_id";
    public static final String SWIYU_API_VERSION_HEADER = "SWIYU-API-Version";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String VP_TOKEN = "vp_token";
    public static final String STATE = "state";
    public static final String DPOP = "DPoP";

    private final RestClient restClient;
    private ServiceLocationContext issuerContext;
    private ServiceLocationContext verifierContext;

    private boolean useEncryption = false;
    private boolean useDPoP = false;
    private boolean signedMetadataPreferred = false;
    private String credentialRequestEncryptionEnc;
    private String credentialResponseEncryptionEnc;
    private KeyPair dpopKeyPair;
    private ECKey dpopPublicKey;
    private MockAttestationAuthority mockAttestationAuthority;

    private final ObjectMapper objectMapper = JsonMapper.builder()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

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

    public Wallet useIssuer(final IssuerHandle issuer) {
        return useIssuer(issuer.serviceLocation());
    }

    public Wallet useIssuer(final ServiceLocationContext issuerContext) {
        this.issuerContext = issuerContext;
        return this;
    }

    public Wallet useVerifier(final VerifierHandle verifier) {
        return useVerifier(verifier.serviceLocation());
    }

    public Wallet useVerifier(final ServiceLocationContext verifierContext) {
        this.verifierContext = verifierContext;
        return this;
    }

    public Wallet useComponents(final IssuerHandle issuer, final VerifierHandle verifier) {
        return useIssuer(issuer).useVerifier(verifier);
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

    public WalletBatchEntry collectTransactionIdFromDeferredOffer(final URI issuerDeepLink) {
        final WalletBatchEntry walletBatchEntry = createWalletBatchEntry();
        return collectTransactionIdFromDeferredOffer(walletBatchEntry, issuerDeepLink);
    }

    public WalletBatchEntry collectTransactionIdFromDeferredOffer(final WalletBatchEntry walletBatchEntry, final URI issuerDeepLink) {
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
        walletBatchEntry.setCredentialConfigurationSupported();

        walletBatchEntry.generateHolderKeys();

        CredentialResponse deferredCredentialTransactionIdResponse = postCredentialRequestWithFreshProofs(walletBatchEntry);

        assertThat(deferredCredentialTransactionIdResponse)
                .isNotNull();

        var transactionIdNode = deferredCredentialTransactionIdResponse.getBody().get(TRANSACTION_ID);
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
            ObjectMapper mapper = JsonMapper.builder()
                    .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                    .build();

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
            final ObjectMapper mapper = JsonMapper.builder()
                    .disable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)
                    .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                    .build();

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
        return extractIssuedCredentials(batchEntry, credentialResponse);
    }

    private List<String> getVerifiableCredentialFromIssuerWithFreshProofs(final WalletBatchEntry batchEntry) {
        CredentialResponse credentialResponse = postCredentialRequestWithFreshProofs(batchEntry);
        return extractIssuedCredentials(batchEntry, credentialResponse);
    }

    private List<String> extractIssuedCredentials(
            final WalletBatchEntry batchEntry,
            final CredentialResponse credentialResponse
    ) {
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

    private CredentialResponse postCredentialRequestWithFreshProofs(final WalletBatchEntry batchEntry) {
        batchEntry.setCNonce(collectCNonce(batchEntry));
        batchEntry.createProofs();

        try {
            return postCredentialRequest(batchEntry);
        } catch (HttpClientErrorException.BadRequest ex) {
            if (!isHolderBindingProofTimeWindowError(ex)) {
                throw ex;
            }

            batchEntry.setCNonce(collectCNonce(batchEntry));
            batchEntry.createProofs();
            return postCredentialRequest(batchEntry);
        }
    }

    private boolean isHolderBindingProofTimeWindowError(final HttpClientErrorException.BadRequest ex) {
        final String body = ex.getResponseBodyAsString();
        return body.contains("\"error\":\"invalid_proof\"")
                && body.contains("Holder Binding proof was not issued at an acceptable time");
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
        } catch (JacksonException e) {
            throw new IllegalStateException("Cannot serialize deferred credential request", e);
        }

        final String finalPayload = useEncryption
                ? encryptCredentialRequest(walletEntry, requestPayload)
                : requestPayload;

        String bearerToken = token.getAccessToken();

        String doPProofForCredentialRequest = null;
        if (DPOP.equals(token.getTokenType())) {
            doPProofForCredentialRequest = DPoPSupport.createDpopProofForToken(
                    deferredCredentialUri.toString(),
                    collectDPoPNonce(walletEntry),
                    dpopKeyPair,
                    dpopPublicKey,
                    token.getAccessToken()
            );
        }

        var requestBuilder = restClient.post()
                .uri(issuerContext.getContextualizedUri(deferredCredentialUri))
                .header(SWIYU_API_VERSION_HEADER, SwiyuApiVersionConfig.V1.getValue())
                .header(HttpHeaders.CONTENT_TYPE, useEncryption ? APPLICATION_JWT : MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + bearerToken);

        if (doPProofForCredentialRequest != null) {
            requestBuilder = requestBuilder.header(DPOP, doPProofForCredentialRequest);
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

        if (credentialResponse.has(TRANSACTION_ID)) {
            final String transactionIdRaw = credentialResponse.get(TRANSACTION_ID).getAsString();
            walletEntry.setTransactionId(UUID.fromString(transactionIdRaw));
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

            var header = new JWEHeader.Builder(
                    JWEAlgorithm.ECDH_ES,
                    EncryptionMethod.parse(resolveCredentialRequestEncryptionEnc(
                            requestEncryptionMetadata.getEncValuesSupported())))
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

    public void respondToVerification(RequestObject requestObject, String token) {
        final ResponseEntity<String> response = respondToVerificationWithVpTokens(requestObject, List.of(token));

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
    }

    public ResponseEntity<String> respondToVerificationWithVpTokens(
            final RequestObject requestObject,
            final List<String> tokens
    ) {
        final String tokenId = requestObject.getDcqlQuery().getCredentials().getFirst().getId();
        final Map<String, Object> vpToken = Map.of(tokenId, tokens);

        final MultiValueMap<String, Object> formData = new LinkedMultiValueMap<>();

        if (useEncryption) {
            formData.add("response", buildEncryptedResponse(requestObject, vpToken));
        } else {
            formData.add(VP_TOKEN, new Gson().toJson(vpToken));

            if (requestObject.getState() != null) {
                formData.add(STATE, requestObject.getState());
            }
        }

        return restClient.post()
                .uri(verifierContext.getContextualizedUri(PathSupport.toUri(requestObject.getResponseUri())))
                .headers(headers -> {
                    headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
                    headers.add(SWIYU_API_VERSION_HEADER, SwiyuApiVersionConfig.V1.getValue());
                })
                .body(formData)
                .retrieve()
                .toEntity(String.class);
    }

    public void respondToVerificationWithError(
            final RequestObject requestObject,
            final String error,
            final String errorDescription
    ) {
        respondToVerificationWithError(
                PathSupport.toUri(requestObject.getResponseUri()),
                requestObject.getState(),
                error,
                errorDescription
        );
    }

    public void respondToVerificationWithError(
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

        final ResponseEntity<String> response = restClient.post()
                .uri(verifierContext.getContextualizedUri(responseUri))
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
        final WalletBatchEntry entry = createWalletBatchEntry();
        return collectOffer(entry, offerDeepLink, null);
    }

    public WalletBatchEntry collectOffer(final URI offerDeepLink, final Integer count) {
        final WalletBatchEntry entry = createWalletBatchEntry();
        return collectOffer(entry, offerDeepLink, count);
    }

    public WalletBatchEntry collectOffer(final WalletBatchEntry entry, final URI offerDeepLink) {
        return collectOffer(entry, offerDeepLink, null);
    }

    public WalletBatchEntry collectOffer(final WalletBatchEntry entry, final URI offerDeepLink, final Integer count) {
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

        int effectiveCount = (count != null)
                ? count
                : entry.getIssuerMetadata().getBatchCredentialIssuance().getBatchSize();
        entry.generateHolderKeys(effectiveCount);

        getVerifiableCredentialFromIssuerWithFreshProofs(entry);

        return entry;
    }

    public CredentialResponse postCredentialRequest(final WalletBatchEntry walletEntry) {
        final URI credentialUri = walletEntry.getIssuerCredentialUri();
        final OAuthToken token = walletEntry.getToken();
        final String bearerToken = token.getAccessToken();

        var proofsDto = new ProofsDto();
        proofsDto.setJwt(walletEntry.getProofsAsJwt());

        var metadata = walletEntry.getIssuerMetadata();
        var requestDto = new CreateCredentialRequest()
                .credentialConfigurationId(walletEntry.getCredentialOffer().getCredentialConfiguraionId())
                .proofs(proofsDto);
        if (this.useEncryption) {
            walletEntry.generateEphemeralEncryptionKey();

            final Map<String, Object> jwk = walletEntry.getEphemeralEncryptionKey().toPublicJWK().toJSONObject();
            var encryptionMetadata = metadata.getCredentialResponseEncryption();
            var responseEncryption = new CredentialResponseEncryption()
                    .enc(resolveCredentialResponseEncryptionEnc(encryptionMetadata.getEncValuesSupported()))
                    .jwk(jwk);

            requestDto.credentialResponseEncryption(responseEncryption);
        }

        final String requestPayload;
        try {
            requestPayload = new ObjectMapper().writeValueAsString(requestDto);
        } catch (JacksonException ex) {
            throw new IllegalStateException("Failed to serialize credential request payload", ex);
        }

        final String finalPayload = useEncryption
                ? encryptCredentialRequest(walletEntry, requestPayload)
                : requestPayload;

        var requestBuilder = restClient.post()
                .uri(issuerContext.getContextualizedUri(credentialUri))
                .header(HttpHeaders.CONTENT_TYPE, useEncryption ? APPLICATION_JWT : MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + bearerToken)
                .header(SWIYU_API_VERSION_HEADER, SwiyuApiVersionConfig.V1.getValue());

        if (this.useDPoP) {
            final String dPoP = generateDpopForCredentialEndpoint(walletEntry);
            requestBuilder = requestBuilder.header(DPOP, dPoP);
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

        if (credentialResponse.has(TRANSACTION_ID)) {
            final String transactionIdRaw = credentialResponse.get(TRANSACTION_ID).getAsString();
            walletEntry.setTransactionId(UUID.fromString(transactionIdRaw));
        }

        final CredentialResponse completeCredentialResponse = new CredentialResponse(responseCode, credentialResponse, rawResponse);

        walletEntry.setCredentialResponse(completeCredentialResponse);

        return completeCredentialResponse;
    }

    String resolveCredentialResponseEncryptionEnc(final List<String> supportedEncValues) {
        return resolveEncryptionEnc(supportedEncValues, credentialResponseEncryptionEnc);
    }

    private String resolveCredentialRequestEncryptionEnc(final List<String> supportedEncValues) {
        return resolveEncryptionEnc(supportedEncValues, credentialRequestEncryptionEnc);
    }

    private String resolveEncryptionEnc(final List<String> supportedEncValues, final String requestedEnc) {
        if (requestedEnc != null) {
            return requestedEnc;
        }

        assertThat(supportedEncValues)
                .as("issuer encryption metadata enc_values_supported")
                .isNotNull()
                .isNotEmpty();

        return supportedEncValues.getFirst();
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
                .header(DPOP, doPProof)
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
                .header(DPOP, doPProof)
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
                .header(DPOP, doPProof)
                .body(params)
                .retrieve()
                .toEntity(OAuthToken.class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        return response.getBody();
    }

    public void postCredentialRequestWithCustomDPoP(WalletBatchEntry batchEntry, String customDpopProof, URI credentialUri) {
        final OAuthToken token = batchEntry.getToken();
        final String bearerToken = token.getAccessToken();
        var proofsDto = new ProofsDto();
        proofsDto.setJwt(batchEntry.getProofsAsJwt());
        var requestDto = new CreateCredentialRequest()
                .credentialConfigurationId(batchEntry.getCredentialOffer().getCredentialConfiguraionId())
                .proofs(proofsDto);

        final String requestPayload;
        try {
            requestPayload = new ObjectMapper().writeValueAsString(requestDto);
        } catch (JacksonException ex) {
            throw new IllegalStateException("Failed to serialize credential request payload", ex);
        }

        var requestBuilder = restClient.post()
                .uri(issuerContext.getContextualizedUri(credentialUri))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + bearerToken);

        if (customDpopProof != null) {
            requestBuilder = requestBuilder.header(DPOP, customDpopProof);
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
            final Map<String, Object> responsePayload = new LinkedHashMap<>();
            responsePayload.put(VP_TOKEN, payload);
            if (requestObject.getState() != null) {
                responsePayload.put(STATE, requestObject.getState());
            }
            final String vpTokenPayload =
                    new ObjectMapper().writeValueAsString(responsePayload);
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
