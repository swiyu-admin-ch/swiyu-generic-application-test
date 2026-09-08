package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustRegistryMockServerConfigurer;
import ch.admin.bj.swiyu.gen.issuer.model.WebhookCallback;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.TestSupportException;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.json.JsonMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.Getter;
import lombok.Setter;

import lombok.extern.slf4j.Slf4j;
import org.apache.http.protocol.HTTP;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.ClearType;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpStatusCode;
import org.mockserver.model.MediaType;
import org.testcontainers.containers.MockServerContainer;

import java.text.ParseException;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

@Getter
@Setter
@Slf4j
public class MockServerClientConfig {

    @SuppressWarnings("java:S1075") // Constant URI is intentional: used only in test/support context
    public static final String ISSUER_CALLBACK_PATH = "/callbacks/issuer";
    @SuppressWarnings("java:S1075") // Constant URI is intentional: used only in test/support context
    public static final String VERIFIER_CALLBACK_PATH = "/callbacks/issuer";
    public static final String MOCKSERVER_HOST = "mockserver:1080";
    private static final String STATUSLIST_URI_PATTERN = "https://" + MOCKSERVER_HOST + "/api/v1/statuslist/%s.jwt";
    private static final List<String> TP2_ROUTE_PATTERNS = List.of(
            "/api/v2/identity-trust-statement.*",
            "/api/v2/verification-query-public-statement.*",
            "/api/v1/trust/vqps-submissions/?",
            "/api/v2/protected-verification-authorization-trust-statement.*",
            "/api/v2/protected-issuance-authorization-trust-statement.*",
            "/api/v2/protected-issuance-trust-list-statement.*",
            "/api/v2/protected-issuance-trust-list/?",
            "/api/v2/non-compliance-trust-list/?",
            "/api/v1/statuslist/tp2-trust-statements\\.jwt"
    );

    private static final Map<String, String> statusListBitsMap = new HashMap<>();
    private final Map<String, String> didLogsById = new ConcurrentHashMap<>();
    private final Map<String, String> statusListsByIssuerDid = new ConcurrentHashMap<>();
    private final Map<String, String> issuerDidByStatusListId = new ConcurrentHashMap<>();
    private final Map<String, IssuerConfig> issuerConfigsByDid = new ConcurrentHashMap<>();
    private final Map<String, VerifierConfig> verifierConfigsByDid = new ConcurrentHashMap<>();
    private String currentStatusList = "";
    private String activeIssuerDid = "";
    private TrustConfig trustConfig;
    private MockAttestationAuthority attestationAuthority;

    private final List<WebhookCallback> receivedIssuerCallbacks = new CopyOnWriteArrayList<>();
    private boolean throwStatusListError = false;
    private volatile boolean corruptStatusListSignature = false;
    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .disable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    public List<WebhookCallback> getIssuerCallbacks() {
        return receivedIssuerCallbacks;
    }

    public void clearIssuerCallbacks() {
        receivedIssuerCallbacks.clear();
    }

    public void enableStatusListError() {
        this.throwStatusListError = true;
        log.debug("Status list error mode ENABLED - subsequent PUT requests will fail");
    }

    public void disableStatusListError() {
        this.throwStatusListError = false;
        log.debug("Status list error mode DISABLED");
    }

    public void enableCorruptStatusListSignature() {
        this.corruptStatusListSignature = true;
        log.debug("Status list signature corruption ENABLED");
    }

    public void disableCorruptStatusListSignature() {
        this.corruptStatusListSignature = false;
        log.debug("Status list signature corruption DISABLED");
    }

    public MockServerClient createMockServerClient(MockServerContainer mockServer,
            IssuerConfig issuerConfig,
            VerifierConfig verifierConfig,
            TrustConfig trustConfig,
            MockAttestationAuthority attestationAuthority) {
        registerIssuer(issuerConfig);
        registerVerifier(verifierConfig);
        registerTrust(trustConfig);
        registerAttestationAuthority(attestationAuthority);
        final MockServerClient mockServerClient = createMockServerClient(mockServer, trustConfig, attestationAuthority);
        registerTp2Routes(mockServerClient, issuerConfig, verifierConfig, trustConfig);
        return mockServerClient;
    }

    public MockServerClient createMockServerClient(MockServerContainer mockServer,
                                                   TrustConfig trustConfig,
                                                   MockAttestationAuthority attestationAuthority) {
        registerTrust(trustConfig);
        registerAttestationAuthority(attestationAuthority);

        final String validFrom = LocalDate.now(ZoneOffset.UTC)
                .minusDays(7)
                .atStartOfDay(ZoneOffset.UTC)
                .toInstant()
                .toString();

        final String validUntil = LocalDate.now(ZoneOffset.UTC)
                .plusDays(7)
                .atStartOfDay(ZoneOffset.UTC)
                .toInstant()
                .toString();
        MockServerClient mockServerClient = new MockServerClient(
                mockServer.getHost(),
                mockServer.getServerPort());

        registerStatusListRoutes(mockServerClient);
        registerDidResolutionRoutes(mockServerClient);
        registerOauthAndCallbacks(mockServerClient);
        registerRenewalRoute(mockServerClient, validFrom, validUntil);
        registerLegacyTrustRoutes(mockServerClient);

        return mockServerClient;
    }

    public void registerIssuer(final IssuerConfig issuerConfig) {
        issuerConfigsByDid.put(issuerConfig.getIssuerDid(), issuerConfig);
        registerDidLog(issuerConfig.getIssuerDid(), issuerConfig.getIssuerDidLog());
        issuerConfig.getAdditionalSigningIdentities().forEach(this::registerIssuer);
    }

    public void registerVerifier(final VerifierConfig verifierConfig) {
        verifierConfigsByDid.put(verifierConfig.getVerifierDid(), verifierConfig);
        registerDidLog(verifierConfig.getVerifierDid(), verifierConfig.getVerifierDidLog());
        verifierConfig.getAdditionalSigningIdentities().forEach(this::registerVerifier);
    }

    public void registerTrust(final TrustConfig trustConfig) {
        this.trustConfig = trustConfig;
        registerDidLog(trustConfig.getTrustDid(), trustConfig.getTrustDidLog());
    }

    public void registerAttestationAuthority(final MockAttestationAuthority attestationAuthority) {
        this.attestationAuthority = attestationAuthority;
        if (attestationAuthority != null) {
            registerDidLog(attestationAuthority.getDid(), attestationAuthority.getDidLog());
        }
    }

    public void replaceDidLog(final String did, final String didLog) {
        registerDidLog(did, didLog);
    }

    public void registerTp2Routes(final MockServerClient mockServerClient,
                                  final IssuerConfig issuerConfig,
                                  final VerifierConfig verifierConfig,
                                  final TrustConfig trustConfig) {
        clearTp2Routes(mockServerClient);
        Tp2TrustRegistryMockServerConfigurer.registerRoutes(
                mockServerClient,
                issuerConfig,
                verifierConfig,
                trustConfig,
                OBJECT_MAPPER
        );
    }

    public String createLegacyIssuanceTrustStatement(final String vct, final IssuerConfig issuerConfig) {
        try {
            return generateTrustStatement(vct, issuerConfig, trustConfig);
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot generate legacy issuance trust statement", e);
        }
    }

    private void clearTp2Routes(final MockServerClient mockServerClient) {
        TP2_ROUTE_PATTERNS.forEach(path ->
                mockServerClient.clear(request().withPath(path), ClearType.EXPECTATIONS)
        );
    }

    public void setCurrentStatusList(final String issuerDid, final String statusList) {
        currentStatusList = statusList;
        activeIssuerDid = issuerDid;
        statusListsByIssuerDid.put(issuerDid, statusList);
        final String statusListId = extractStatusListIdFromPath(statusList);
        if (statusListId != null) {
            issuerDidByStatusListId.put(statusListId, issuerDid);
        }
    }

    private void registerDidLog(final String did, final String didLog) {
        didLogsById.put(extractDidId(did), didLog);
    }

    private void registerStatusListRoutes(MockServerClient mockServerClient) {
        mockServerClient.when(
                request()
                    .withMethod("GET")
                    .withPath("/api/v1/statuslist/[a-zA-Z0-9-_]+\\.jwt"))
                .respond(httpRequest -> {
                    log.info("Entered GET expectation for status list retrieval with path: {}", httpRequest.getPath().getValue());
                    return response()
                            .withHeader(HTTP.CONTENT_TYPE, "application/statuslist+jwt")
                            .withStatusCode(HttpStatusCode.OK_200.code())
                            .withBody(getStatusListJwt(httpRequest, issuerConfigForStatusList(httpRequest)));
                        });
        mockServerClient.when(
                request()
                        .withMethod("POST")
                        .withPath("/api/v1/status/business-entities/{businessId}/status-list-entries/")
                        .withPathParameter("businessId", ".*"))
                .respond(httpRequest -> {
                    log.info("Entered POST expectation for status list creation with path: {}", httpRequest.getPath().getValue());
                    var id = UUID.randomUUID();
                    var payload = "{\"id\": \"%s\", \"statusRegistryUrl\": \"%s\"}"
                            .formatted(id, STATUSLIST_URI_PATTERN.formatted(id));
                    return response()
                            .withStatusCode(200)
                            .withHeader(HTTP.CONTENT_TYPE, "application/json")
                            .withBody(payload);
                });
        mockServerClient.when(request().withMethod("PUT").withPath(
                "/api/v1/status/business-entities/{businessId}/status-list-entries/{statusListId}")
                .withPathParameter("businessId", ".*").withPathParameter("statusListId", ".*"))
                .respond(httpRequest -> {
                    log.info("Entered PUT expectation for status list update with path: {}", httpRequest.getPath().getValue());

                    if (throwStatusListError) {
                        log.debug("Status list error mode enabled - returning 500 error");
                        return response()
                                .withStatusCode(500)
                                .withHeader(HTTP.CONTENT_TYPE, "application/json")
                                .withBody("{\"error\": \"Internal server error - status list update failed\"}");
                    }

                    try {
                        final String path = httpRequest.getPath().getValue();
                        final String statusListId = extractStatusListIdFromPath(path);

                        final String jwtBody = httpRequest.getBodyAsString();
                        final String bits = extractBitsFromJwt(jwtBody);

                        if (bits != null && statusListId != null) {
                            statusListBitsMap.put(statusListId, bits);
                        }
                    } catch (Exception e) {
                        return response().withStatusCode(500);
                    }
                    return response().withStatusCode(202);
                });
    }

    private void registerDidResolutionRoutes(MockServerClient mockServerClient) {
        mockServerClient
                .when(request()
                        .withMethod("GET")
                        .withPath("/api/v1/did/.*/did.jsonl"))
                .respond(httpRequest -> {

                    String requestedDidId = extractDidIdFromPath(httpRequest.getPath().getValue());
                    final String didLog = didLogsById.get(requestedDidId);

                    if (didLog != null) {
                        return response()
                                .withStatusCode(200)
                                .withHeader(HTTP.CONTENT_TYPE, "application/jsonl+json")
                                .withBody(didLog);
                    }

                    return response().withStatusCode(404);
                });
    }

    private void registerOauthAndCallbacks(MockServerClient mockServerClient) {
        mockServerClient.when(request().withMethod("POST").withPath("/openid-connect/token"))
                .respond(response().withStatusCode(200).withContentType(MediaType.APPLICATION_JSON)
                        .withBody("{\"access_token\": \"access_token\", \"refresh_token\": \"refresh_token\"}"));

        mockServerClient.when(request().withMethod("POST").withPath(ISSUER_CALLBACK_PATH))
                .respond(httpRequest -> {
                    final WebhookCallback callback = OBJECT_MAPPER.readValue(
                            httpRequest.getBodyAsString(),
                            WebhookCallback.class
                    );
                    receivedIssuerCallbacks.add(callback);
                    return response()
                            .withStatusCode(204)
                            .withContentType(MediaType.APPLICATION_JSON);
                });

        mockServerClient.when(request().withMethod("POST").withPath(VERIFIER_CALLBACK_PATH))
                .respond(response().withStatusCode(204).withContentType(MediaType.APPLICATION_JSON));
    }

    private void registerRenewalRoute(MockServerClient mockServerClient, String validFrom, String validUntil) {
        mockServerClient
                .when(request().withMethod("POST").withPath("/renewal"))
                .respond(httpRequest -> {
                    try {
                        return response()
                                .withStatusCode(200)
                                .withHeader(HTTP.CONTENT_TYPE, "application/json")
                                .withBody(new ObjectMapper().writeValueAsString(
                                        Map.of(
                                                "metadata_credential_supported_id", List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT),
                                                "credential_subject_data", CredentialSubjectFixtures.completeEmployeeProfile(),
                                                "credential_metadata", Map.of("vct#integrity","sha256-0000000000000000000000000000000000000000000="),
                                                "credential_valid_from", validFrom,
                                                "credential_valid_until", validUntil,
                                                "status_lists", List.of(currentRenewalStatusList(httpRequest)))));
                    } catch (JacksonException e) {
                        throw new TestSupportException("Cannot parse correctly data");
                    }
                });
    }

    private void registerLegacyTrustRoutes(MockServerClient mockServerClient) {
        mockServerClient.when(
                        request()
                                .withMethod("GET")
                                .withPath(".*/api/v1/truststatements/issuance")
                )
                .respond(httpRequest -> {
                    try {
                        String path = httpRequest.getPath().getValue();
                        String vct = firstPresentQueryParameter(httpRequest, "vcSchemaId", "schemaId", "vct");

                        if (path.startsWith("/trusted/")) {
                            final List<String> trustStatements = new ArrayList<>();
                            for (IssuerConfig issuerConfig : issuerConfigsByDid.values()) {
                                trustStatements.add(generateTrustStatement(vct, issuerConfig, trustConfig));
                            }

                            return response()
                                    .withStatusCode(200)
                                    .withHeader(HTTP.CONTENT_TYPE, "application/json")
                                    .withBody(OBJECT_MAPPER.writeValueAsString(trustStatements));
                        }
                        return response()
                                .withStatusCode(200)
                                .withHeader(HTTP.CONTENT_TYPE, "application/json")
                                .withBody("[]");
                    } catch (Exception e) {
                        return response().withStatusCode(500);
                    }
                });
    }

    private String firstPresentQueryParameter(HttpRequest httpRequest, String... names) {
        for (String name : names) {
            String value = httpRequest.getFirstQueryStringParameter(name);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private String extractDidIdFromPath(String path) {
        String normalized = path.endsWith("/did.jsonl") ? path.substring(0, path.length() - "/did.jsonl".length()) : path;
        return normalized.substring(normalized.lastIndexOf("/") + 1);
    }

    private String extractDidId(String did) {
        return did.substring(did.lastIndexOf(":") + 1);
    }

    private String generateTrustStatement(String vct, IssuerConfig issuerConfig, TrustConfig trustConfig)
            throws JOSEException {

        // Vérifier que la clé de confiance est disponible
        if (trustConfig.getTrustAssertKeyPemString() == null || trustConfig.getTrustAssertKeyPemString().isEmpty()) {
            log.error("Trust key PEM not available, cannot generate trust statement");
            throw new JOSEException("Trust key is not available");
        }

        final JWK trustJwk = JWK.parseFromPEMEncodedObjects(trustConfig.getTrustAssertKeyPemString());
        final JWSSigner signer = new ECDSASigner(trustJwk.toECKey());

        final String issuerDid = issuerConfig.getIssuerDid();

        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(trustConfig.getTrustDid())
                .subject(issuerDid)
                .claim("vct", "TrustStatementIssuanceV1")
                .claim("canIssue", vct)
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                .build();

        final SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .keyID(trustConfig.getTrustAssertKeyId())
                        .type(new JOSEObjectType("vc+sd-jwt"))
                        .build(),
                claimsSet);

        signedJWT.sign(signer);

        return signedJWT.serialize() + "~";
    }

    private IssuerConfig firstIssuerConfig() {
        return issuerConfigsByDid.values().stream()
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No issuer config registered in MockServerClientConfig"));
    }

    private IssuerConfig issuerConfigForStatusList(final HttpRequest httpRequest) {
        final String statusListId = extractStatusListIdFromPath(httpRequest.getPath().getValue());
        if (statusListId == null) {
            return firstIssuerConfig();
        }

        final String issuerDid = issuerDidByStatusListId.get(statusListId);
        if (issuerDid == null) {
            return firstIssuerConfig();
        }

        return Optional.ofNullable(issuerConfigsByDid.get(issuerDid))
                .orElseGet(this::firstIssuerConfig);
    }

    private String currentRenewalStatusList(final HttpRequest httpRequest) {
        final String requestedIssuerDid = httpRequest.getFirstQueryStringParameter("issuerDid");
        if (requestedIssuerDid != null && !requestedIssuerDid.isBlank()) {
            final String statusList = statusListsByIssuerDid.get(requestedIssuerDid);
            if (statusList != null) {
                return statusList;
            }
        }
        if (activeIssuerDid != null && !activeIssuerDid.isBlank()) {
            final String statusList = statusListsByIssuerDid.get(activeIssuerDid);
            if (statusList != null) {
                return statusList;
            }
        }
        return currentStatusList;
    }

    private String getStatusListJwt(HttpRequest httpRequest, IssuerConfig issuerConfig)
            throws JOSEException, ParseException {

        final JWK jwk = KeyUtil.createJWKFromKeyPair(issuerConfig.getKeyPair());

        final JWSSigner signer = new ECDSASigner(jwk.toECKey());

        final String path = httpRequest.getPath().getValue();
        final String statusListId = extractStatusListIdFromPath(path);

        final String statusBits = statusListBitsMap.getOrDefault(statusListId,
                "eNrtwQEBAAAAgiD_r25IQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHwYYagAAQ");
        final Date issuedAt = new Date();

        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(STATUSLIST_URI_PATTERN.formatted(statusListId))
                .issuer(issuerConfig.getIssuerDid())
                .issueTime(issuedAt)
                .claim("status_list", Map.of(
                        "bits", "2",
                        "lst", statusBits))
                .expirationTime(new Date(issuedAt.getTime() + 60 * 1000))
                .build();

        final SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .keyID(issuerConfig.getIssuerAssertKeyId())
                        .type(new JOSEObjectType("statuslist+jwt"))
                        .build(),
                claimsSet);

        signedJWT.sign(signer);

        final String serializedStatusList = signedJWT.serialize();
        return corruptStatusListSignature
                ? corruptJwtSignature(serializedStatusList)
                : serializedStatusList;
    }

    private String corruptJwtSignature(final String jwt) {
        final String[] parts = jwt.split("\\.", -1);
        if (parts.length != 3 || parts[2].isEmpty()) {
            throw new IllegalArgumentException("JWT must be a compact JWS with a signature");
        }

        final char replacement = parts[2].charAt(0) == 'A' ? 'B' : 'A';
        parts[2] = replacement + parts[2].substring(1);
        return String.join(".", parts);
    }

    private String extractStatusListIdFromPath(String path) {
        if (path == null) return null;

        final int lastSlash = path.lastIndexOf('/');
        if (lastSlash < 0) return null;

        final String lastSegment = path.substring(lastSlash + 1);

        if (lastSegment.endsWith(".jwt")) {
            return lastSegment.substring(0, lastSegment.length() - 4);
        }

        return lastSegment;
    }

    private String extractBitsFromJwt(String jwtBody) {
        try {
            if (jwtBody == null || jwtBody.isEmpty()) {
                return null;
            }

            String decodedBody;
            try {
                byte[] decoded = java.util.Base64.getDecoder().decode(jwtBody);
                decodedBody = new String(decoded);
            } catch (IllegalArgumentException e) {
                decodedBody = jwtBody;
            }

            final SignedJWT jwt = SignedJWT.parse(decodedBody);
            final Map<String, Object> claims = jwt.getJWTClaimsSet().getClaims();

            if (claims.containsKey("status_list")) {
                @SuppressWarnings("unchecked")
                final Map<String, Object> statusListClaim = (Map<String, Object>) claims.get("status_list");
                return (String) statusListClaim.get("lst");
            }
        } catch (ParseException e) {
            return null;
        }
        return null;
    }
}
