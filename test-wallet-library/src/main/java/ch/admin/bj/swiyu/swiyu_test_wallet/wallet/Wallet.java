package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.gen.issuer.model.*;
import ch.admin.bj.swiyu.gen.verifier.model.JsonWebKey;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerMetadata;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
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
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.JsonConverter.toJsonNode;
import static java.util.Objects.nonNull;
import static org.assertj.core.api.Assertions.assertThat;


@Getter
@Setter
public class Wallet {

    public static final String BEARER_PREFIX = "Bearer ";
    public static final String VC_SD_JWT = "vc+sd-jwt";

    private final RestClient restClient;
    private final ServiceLocationContext issuerContext;
    private final ServiceLocationContext verifierContext;

    private boolean encryptionPreferred = false;

    public Wallet(RestClient restClient, ServiceLocationContext issuerContext, ServiceLocationContext verifierContext) {
        this.restClient = restClient;
        this.issuerContext = issuerContext;
        this.verifierContext = verifierContext;
    }

    public Wallet(RestClient restClient, ServiceLocationContext issuerContext, ServiceLocationContext verifierContext, boolean encryptionPreferred) {
        this(restClient, issuerContext, verifierContext);
        this.encryptionPreferred = encryptionPreferred;
    }

    private static String decryptJWE(RSAKey jwk, String encryptedVerifiableCredential) {
        try {
            JWEObject jweObject = JWEObject.parse(encryptedVerifiableCredential);
            jweObject.decrypt(new RSADecrypter(jwk));
            return jweObject.getPayload().toString();
        } catch (JOSEException | ParseException e) {
            throw new RuntimeException("Unable to parse encrypted issuer credentials", e);
        }
    }

    private static String decryptJWE(ECKey walletEphemeralKey, String encryptedResponse) {
        try {
            JWEObject jweObject = JWEObject.parse(encryptedResponse);
            jweObject.decrypt(new ECDHDecrypter(walletEphemeralKey));
            return jweObject.getPayload().toString();
        } catch (JOSEException | ParseException e) {
            throw new RuntimeException("Unable to decrypt ECDH-ES issuer credential response", e);
        }
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

    public WalletEntry createWalletEntry() {
        return new WalletEntry(this);
    }

    public WalletEntry collectOffer(URI offerDeepLink) {
        final WalletEntry walletEntry = createWalletEntry();
        walletEntry.receiveDeepLinkAndValidateIt(issuerContext.getContextualizedUri(offerDeepLink));
        walletEntry.setIssuerWellKnownConfiguration(getIssuerWellKnownConfiguration(walletEntry));
        walletEntry.setToken(collectToken(walletEntry));
        walletEntry.setIssuerMetadata(getIssuerWellKnownMetadata(walletEntry));
        walletEntry.setCredentialConfigurationSupported();
        walletEntry.setIssuerSdJwt(getVerifiableCredentialFromIssuer(walletEntry));
        return walletEntry;
    }

    public WalletEntry collectTransactionIdFromDeferredOffer(URI issuerDeepLink) {
        var walletEntry = createWalletEntry();

        walletEntry.receiveDeepLinkAndValidateIt(issuerDeepLink);
        walletEntry.setIssuerWellKnownConfiguration(getIssuerWellKnownConfiguration(walletEntry));
        walletEntry.setToken(collectToken(walletEntry));
        walletEntry.setIssuerMetadata(getIssuerWellKnownMetadata(walletEntry));
        walletEntry.setCredentialConfigurationSupported();
        var deferredCredentialTransactionIdResponse = postCredentialRequest(walletEntry);

        assertThat(deferredCredentialTransactionIdResponse)
                .isNotNull();

        var transactionIdNode = deferredCredentialTransactionIdResponse.get("transaction_id");
        assertThat(transactionIdNode).isNotNull();
        var transactionId = transactionIdNode.getAsString();
        assertThat(transactionId).isNotNull();

        walletEntry.setTransactionId(UUID.fromString(transactionId));
        return walletEntry;
    }

    public OpenIdConfiguration getIssuerWellKnownConfiguration(WalletEntry walletEntry) {
        URI credentialIssuerURI = issuerContext.getContextualizedUri(walletEntry.getCredentialOffer().getCredentialIssuerUri());
        URI target = credentialIssuerURI.resolve("oid4vci/.well-known/openid-configuration");

        return restClient.get()
                .uri(target)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .retrieve()
                .body(OpenIdConfiguration.class);
    }

    public IssuerMetadata getIssuerWellKnownMetadata(WalletEntry walletEntry) {
        var issuerUri = issuerContext.getContextualizedUri(walletEntry.getIssuerUri());
        var issuerMetadataUri = issuerUri.resolve("oid4vci/.well-known/openid-credential-issuer");

        @SuppressWarnings("unchecked")
        Map<String, Object> rawMetadata = restClient.get()
                .uri(issuerMetadataUri)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
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

    public NonceResponse getCNonce(WalletEntry walletEntry) {
        final ResponseEntity<NonceResponse> response = restClient.post()
                .uri(walletEntry.getIssuerMetadata().getNonceEndpointURI())
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .retrieve()
                .toEntity(NonceResponse.class);
        return response.getBody();
    }

    public String getVerifiableCredentialFromIssuer(WalletEntry walletEntry) {
        var bodyAsJson = postCredentialRequest(walletEntry);

        if (walletEntry.isEncryptionEnabled()) {
            assertThat(bodyAsJson).isNotNull();

            final JsonElement credentialsElement = bodyAsJson.get("credentials");
            assertThat(credentialsElement).isNotNull();
            assertThat(credentialsElement.isJsonArray()).isTrue();

            final JsonArray credentialsArray = credentialsElement.getAsJsonArray();
            assertThat(credentialsArray.size()).isGreaterThan(0);

            final JsonObject firstCredential = credentialsArray.get(0).getAsJsonObject();
            assertThat(firstCredential.has("credential")).isTrue();

            return firstCredential.get("credential").getAsString();

        }

        assertThat(bodyAsJson.get("format").getAsString()).isEqualTo(VC_SD_JWT);
        assertThat(bodyAsJson.get("credential")).isNotNull();

        return bodyAsJson.get("credential").getAsString();
    }

    public List<String> getVerifiableCredentialFromIssuer(WalletBatchEntry batchEntry) {
        var response = postCredentialRequest(batchEntry);

        assertThat(response).isNotNull();
        var credentialsElement = response.get("credentials");
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


    private JsonObject postCredentialRequest(final WalletEntry walletEntry) {
        final boolean isEncryptionEnabled = walletEntry.isEncryptionEnabled();
        final boolean isBatch = walletEntry instanceof WalletBatchEntry batchEntry;

        var credentialUri = walletEntry.getIssuerCredentialUri();
        var token = walletEntry.getToken();
        var bearerToken = token.getAccessToken();

        String requestPayload;
        ResponseEntity<String> response;

        if (isBatch) {
            var metadata = walletEntry.getIssuerMetadata();
            var proofsDto = new ProofsDto();
            proofsDto.setJwt(((WalletBatchEntry) walletEntry).getProofsAsJwt());

            walletEntry.generateEphemeralEncryptionKey();

            var encryptionMetadata = metadata.getCredentialResponseEncryption();
            var responseEncryption = new CredentialResponseEncryption();
            responseEncryption.setAlg(encryptionMetadata.getAlgValuesSupported().getFirst());
            responseEncryption.setEnc(encryptionMetadata.getEncValuesSupported().getFirst());
            responseEncryption.setJwk(walletEntry.getEphemeralEncryptionKey().toPublicJWK().toJSONObject());

            var credentialConfigId = walletEntry.getCredentialOffer().getCredentialConfiguraionId();
            var requestV2 = new CredentialEndpointRequestV2()
                    .credentialConfigurationId(credentialConfigId)
                    .proofs(proofsDto);

            if (isEncryptionEnabled) {
                requestV2.credentialResponseEncryption(responseEncryption);
            }

            try {
                requestPayload = new ObjectMapper().writeValueAsString(requestV2);
            } catch (JsonProcessingException ex) {
                throw new RuntimeException("Cannot serialize payload credential", ex);
            }

            if (isEncryptionEnabled) {
                requestPayload = encryptCredentialRequest(walletEntry, requestPayload);
            }

            response = restClient.post()
                    .uri(issuerContext.getContextualizedUri(credentialUri))
                    .header(HttpHeaders.CONTENT_TYPE, isEncryptionEnabled ? "application/jwt" : MediaType.APPLICATION_JSON_VALUE)
                    .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + bearerToken)
                    .header("SWIYU-API-Version", "2")
                    .body(requestPayload)
                    .retrieve()
                    .toEntity(String.class);

        } else if (isEncryptionEnabled) {
            final IssuerMetadata metadata = walletEntry.getIssuerMetadata();
            final ProofsDto proofsDto = new ProofsDto();
            final String proof = walletEntry.createProof().toJwt();
            proofsDto.setJwt(List.of(proof));

            walletEntry.generateEphemeralEncryptionKey();

            var encryptionMetadata = metadata.getCredentialResponseEncryption();

            final CredentialResponseEncryption responseEncryption = new CredentialResponseEncryption();
            responseEncryption.setAlg(encryptionMetadata.getAlgValuesSupported().getFirst());
            responseEncryption.setEnc(encryptionMetadata.getEncValuesSupported().getFirst());
            responseEncryption.setJwk(walletEntry.getEphemeralEncryptionKey().toPublicJWK().toJSONObject());

            var credentialConfigId = walletEntry.getCredentialOffer().getCredentialConfiguraionId();
            var requestV2 = new CredentialEndpointRequestV2()
                    .credentialConfigurationId(credentialConfigId)
                    .proofs(proofsDto)
                    .credentialResponseEncryption(responseEncryption);

            try {
                requestPayload = new ObjectMapper().writeValueAsString(requestV2);
            } catch (JsonProcessingException ex) {
                throw new RuntimeException("Cannot serialize payload credential", ex);
            }

            requestPayload = encryptCredentialRequest(walletEntry, requestPayload);

            response = restClient.post()
                    .uri(issuerContext.getContextualizedUri(credentialUri))
                    .header(HttpHeaders.CONTENT_TYPE, "application/jwt")
                    .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + bearerToken)
                    .header("SWIYU-API-Version", "2")
                    .body(requestPayload)
                    .retrieve()
                    .toEntity(String.class);

        } else {
            var credentialConfigurationSupported = walletEntry.getCredentialConfigurationSupported();
            var request = new CredentialEndpointRequest();
            request.setFormat(VC_SD_JWT);

            if (credentialConfigurationSupported.has("proof_types_supported")) {
                var proof = walletEntry.createProof().toJwt();
                Map<String, Object> proofMap = Map.of("proof_type", "jwt", "jwt", proof);
                request.setProof(proofMap);
            }

            try {
                requestPayload = new ObjectMapper().writeValueAsString(request);
            } catch (JsonProcessingException ex) {
                throw new RuntimeException("Cannot serialize payload credential", ex);
            }

            response = restClient.post()
                    .uri(issuerContext.getContextualizedUri(credentialUri))
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + bearerToken)
                    .body(requestPayload)
                    .retrieve()
                    .toEntity(String.class);
        }

        int responseStatusCode = response.getStatusCode().value();
        String bodyAsString = response.getBody();

        assertThat(responseStatusCode)
                .withFailMessage("POST issuer credential request failed: url [%s], code [%d], body [%s], request [encrypted=%s, batch=%s]"
                        .formatted(credentialUri, responseStatusCode, bodyAsString, isEncryptionEnabled, isBatch))
                .isIn(List.of(200, 202));

        if (isEncryptionEnabled) {
            try {
                bodyAsString = decryptJWE(walletEntry.getEphemeralEncryptionKey(), bodyAsString);
            } catch (Exception e) {
                throw new RuntimeException("Error during decryption", e);
            }
        }

        var credentialResponse = JsonParser.parseString(bodyAsString).getAsJsonObject();

        if (isBatch && credentialResponse.has("credentials")) {
            var array = credentialResponse.getAsJsonArray("credentials");
            array.forEach(el -> {
                var credential = el.getAsJsonObject().get("credential").getAsString();
                ((WalletBatchEntry) walletEntry).addIssuedCredential(credential);
            });
        } else if (nonNull(credentialResponse.get("credential"))) {
            walletEntry.setIssuerSdJwt(credentialResponse.get("credential").getAsString());
        }

        return credentialResponse;
    }



    private JsonObject postDeferredCredentialRequest(WalletEntry walletEntry) {
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
        String bearerToken = token.getAccessToken();

        ResponseEntity<String> response = restClient.post()
                .uri(issuerContext.getContextualizedUri(deferredCredentialUri))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + bearerToken)
                .body(requestPayload)
                .retrieve()
                .toEntity(String.class); // Use toEntity for status + body

        int responseStatusCode = response.getStatusCode().value();
        String bodyAsString = response.getBody();

        assertThat(responseStatusCode)
                .withFailMessage("POST issuer credential request failed: url [%s], response code [%d] and response body [%s], request body: [%s]"
                        .formatted(deferredCredentialUri, responseStatusCode, bodyAsString, requestPayload))
                .isIn(List.of(200, 202));

        var credentialResponse = JsonParser.parseString(bodyAsString).getAsJsonObject();

        walletEntry.setIssuerSdJwt(credentialResponse.get("credential").getAsString());

        return credentialResponse;
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


    private CredentialResponseEncryption createCredentialResponseEncryption(RSAKey encrypterJwk) {
        var credentialResponseEncryption = new CredentialResponseEncryption();
        if (encrypterJwk != null) {
            credentialResponseEncryption.setAlg("ECDH-E");
            credentialResponseEncryption.setEnc("A256GCM");
            credentialResponseEncryption.setJwk(Map.of(
                    "kty", encrypterJwk.getKeyType().getValue(),
                    "e", encrypterJwk.getPublicExponent().toString(),
                    "n", encrypterJwk.getModulus().toString()
            ));
        }

        return credentialResponseEncryption;
    }

    public JsonObject getCredentialFromTransactionId(WalletEntry walletEntry) {
        return postDeferredCredentialRequest(walletEntry);
    }

    public RequestObject getVerificationDetails(String verificationDeeplink) {
        var query = URI.create(verificationDeeplink).getQuery();

        String[] pairs = query.split("&");
        var verificationUrl = verifierContext.getContextualizedUri(PathSupport.toUri(pairs[1].split("=")[1]));

        return restClient.get()
                .uri(verificationUrl)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .retrieve()
                .body(RequestObject.class);
    }

    public void respondToVerification(RequestObject requestObject, String token) {

        var submission = getPresentationSubmissionPayload();

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();

        if (requestObject.getResponseMode() == RequestObject.ResponseModeEnum.POST_JWT) {
            final JsonWebKey jsonWebKey = requestObject.getClientMetadata().getJwks().getKeys().getFirst();
            final ECKey verifierKey = new ECKey.Builder(
                    Curve.parse(jsonWebKey.getCrv()),
                    new Base64URL(jsonWebKey.getX()),
                    new Base64URL(jsonWebKey.getY())
            )
            .keyID(jsonWebKey.getKid())
            .build();

            final String encAlg = requestObject.getClientMetadata().getEncryptedResponseEncValuesSupported().getFirst();
            final EncryptionMethod encryptionMethod = EncryptionMethod.parse(encAlg);

            final JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, encryptionMethod)
                    .keyID(verifierKey.getKeyID())
                    .build();
            final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .claim("presentation_submission", submission)
                    .claim("vp_token", token)
                    .build();
            final JWEObject jweObject = new JWEObject(jweHeader, claimsSet.toPayload());
            try {
                jweObject.encrypt(new ECDHEncrypter(verifierKey.toECKey()));
            } catch (JOSEException e) {
                throw new RuntimeException("Failed to encrypt VP token response", e);
            }
            formData.add("response", jweObject.serialize());
        } else {
            formData.add("presentation_submission", submission);
            formData.add("vp_token", token);
        }

        var response = restClient.post()
                .uri(verifierContext.getContextualizedUri(PathSupport.toUri(requestObject.getResponseUri())))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .body(formData)
                .retrieve()
                .toBodilessEntity();
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
    }

    public void respondToVerificationV2(RequestObject requestObject, String token, String tokenId) {

        var vpToken = Map.of(tokenId, List.of(token));

        MultiValueMap<String, Object> formData = new LinkedMultiValueMap<>();
        formData.add("vp_token", new Gson().toJson(vpToken));

        var response = restClient.post()
                .uri(verifierContext.getContextualizedUri(PathSupport.toUri(requestObject.getResponseUri())))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .header("SWIYU-API-Version", "2")
                .body(formData)
                .retrieve()
                .toBodilessEntity();
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
    }

//    public void rejectVerificationRequest(VerificationRequestDetails verificationDetails) {
//        var target = verificationDetails.getOid4vpResponseUri();
//        var formData = new LinkedMultiValueMap<String, String>();
//        formData.add("error", "client_rejected");
//
//        var response = restClient.post()
//                .uri(target)
//                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
//                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
//                .body(formData)
//                .retrieve()
//                .toBodilessEntity();
//
//        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
//    }

    public JsonNode getVctDetailsFromVctAsUrl(WalletEntry walletEntry) {
        var vctUri = walletEntry.getVctUri();
        String bodyAsString = restClient.get().uri(vctUri).exchange((req, resp) -> {
            var body = resp.bodyTo(String.class);
            assertThat(resp.getStatusCode().value())
                    .withFailMessage("url: %s%nbody: %s".formatted(vctUri, body))
                    .isEqualTo(200);
            return body;
        });

        return toJsonNode(bodyAsString);

    }

    public WalletBatchEntry createWalletBatchEntry() {
        return new WalletBatchEntry(this);
    }

    public WalletBatchEntry collectOfferBatch(URI offerDeepLink, int holderCount) {
        var entry = createWalletBatchEntry();
        entry.receiveDeepLinkAndValidateIt(issuerContext.getContextualizedUri(offerDeepLink));
        entry.setIssuerWellKnownConfiguration(getIssuerWellKnownConfiguration(entry));
        entry.setToken(collectToken(entry));
        entry.setIssuerMetadata(getIssuerWellKnownMetadata(entry));
        entry.setCredentialConfigurationSupported();

        entry.generateHolderKeys(holderCount);
        entry.createProofs();

        getVerifiableCredentialFromIssuer(entry);

        return entry;
    }
}
