package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.gen.issuer.model.CredentialEndpointRequest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialResponseEncryption;
import ch.admin.bj.swiyu.gen.issuer.model.DeferredCredentialEndpointRequest;
import ch.admin.bj.swiyu.gen.issuer.model.NonceResponse;
import ch.admin.bj.swiyu.gen.issuer.model.OAuthToken;
import ch.admin.bj.swiyu.gen.issuer.model.OpenIdConfiguration;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerMetadata;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.JsonConverter.toJsonNode;
import static java.util.Objects.nonNull;
import static org.assertj.core.api.Assertions.assertThat;


public class Wallet {

    public static final String BEARER_PREFIX = "Bearer ";
    public static final String VC_SD_JWT = "vc+sd-jwt";

    private final RestClient restClient;
    private final ServiceLocationContext context;
    private final ServiceLocationContext verifierContext;

    public Wallet(RestClient restClient, ServiceLocationContext context, ServiceLocationContext verifierContext) {
        this.restClient = restClient;
        this.context = context;
        this.verifierContext = verifierContext;
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

    public WalletEntry createEmptyWalletEntry() {
        return new WalletEntry(null);
    }

    public WalletEntry collectOffer(URI offerDeepLink) {
        var walletEntry = new WalletEntry(restClient);
        walletEntry.receiveDeepLinkAndValidateIt(context.getContextualizedUri(offerDeepLink));
        walletEntry.setIssuerWellKnownConfiguration(getIssuerWellKnownConfiguration(walletEntry));
        walletEntry.setToken(collectToken(walletEntry));
        walletEntry.setIssuerMetadata(getIssuerWellKnownMetadata(walletEntry));
        walletEntry.setCredentialConfigurationSupported();
        walletEntry.setIssuerSdJwt(getVerifiableCredentialFromIssuer(walletEntry));
        return walletEntry;
    }

    public WalletEntry collectTransactionIdFromDeferredOffer(URI issuerDeepLink) {
        var walletEntry = createEmptyWalletEntry();

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
        URI credentialIssuerURI = context.getContextualizedUri(walletEntry.getCredentialOffer().getCredentialIssuerUri());
        URI target = credentialIssuerURI.resolve("oid4vci/.well-known/openid-configuration");

        return restClient.get()
                .uri(target)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .retrieve()
                .body(OpenIdConfiguration.class);
    }

    public IssuerMetadata getIssuerWellKnownMetadata(WalletEntry walletEntry) {
        var issuerUri = context.getContextualizedUri(walletEntry.getIssuerUri());
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
        var tokenUri = context.getContextualizedUri(walletEntry.getIssuerTokenUri());
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

        assertThat(bodyAsJson.get("format").getAsString()).isEqualTo(VC_SD_JWT);
        assertThat(bodyAsJson.get("credential")).isNotNull();

        return bodyAsJson.get("credential").getAsString();
    }

    private JsonObject postCredentialRequest(WalletEntry walletEntry) {
        var credentialConfigurationSupported = walletEntry.getCredentialConfigurationSupported();

        var credentialUri = walletEntry.getIssuerCredentialUri();
        var token = walletEntry.getToken();
        var request = new CredentialEndpointRequest();
        request.setFormat(VC_SD_JWT);

        if (credentialConfigurationSupported.has("proof_types_supported")) {
            var proof = walletEntry.createProof().toJwt();
            Map<String, Object> proofMap = Map.of("proof_type", "jwt", "jwt", proof);
            request.setProof(proofMap);
        }

        String requestPayload = null;
        try {
            requestPayload = new ObjectMapper().writeValueAsString(request);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        String bearerToken = token.getAccessToken();

        ResponseEntity<String> response = restClient.post()
                .uri(context.getContextualizedUri(credentialUri))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + bearerToken)
                .body(requestPayload)
                .retrieve()
                .toEntity(String.class); // Use toEntity for status + body

        int responseStatusCode = response.getStatusCode().value();
        String bodyAsString = response.getBody();

        assertThat(responseStatusCode)
                .withFailMessage("POST issuer credential request failed: url [%s], response code [%d] and response body [%s], request body: [%s]"
                        .formatted(credentialUri, responseStatusCode, bodyAsString, requestPayload))
                .isIn(List.of(200, 202));

        var credentialResponse = JsonParser.parseString(bodyAsString).getAsJsonObject();

        if (nonNull(credentialResponse.get("credential"))) {
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
                .uri(context.getContextualizedUri(deferredCredentialUri))
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

    private CredentialResponseEncryption createCredentialResponseEncryption(RSAKey encrypterJwk) {
        var credentialResponseEncryption = new CredentialResponseEncryption();
        if (encrypterJwk != null) {
            credentialResponseEncryption.setAlg("RSA-OAEP-256");
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
        formData.add("presentation_submission", submission);
        formData.add("vp_token", token);

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
}
