package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.gen.verifier.model.ConfigurationOverrideDto;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustRegistryMockServerConfigurer;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JwtSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockserver.matchers.TimeToLive;
import org.mockserver.matchers.Times;
import org.mockserver.model.ClearType;
import org.mockserver.model.HttpRequest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpStatusCodeException;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.awaitility.Awaitility.await;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierTSCache extends BaseTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().findAndRegisterModules();
    private static final Duration CACHED_TRUST_STATEMENT_LIFETIME = Duration.ofMinutes(5);
    private static final Duration SHORT_TRUST_STATEMENT_LIFETIME = Duration.ofSeconds(5);
    private static final String IDENTITY_TRUST_STATEMENT_PATH = "/api/v2/identity-trust-statement";
    private static final String PROTECTED_VERIFICATION_AUTHORIZATION_PATH =
            "/api/v2/protected-verification-authorization-trust-statement";
    private static final String TP2_PROFILE_VERSION = "swiss-profile-trust:1.0.0";
    private static final String IDENTITY_TRUST_STATEMENT_TYPE = "swiyu-identity-trust-statement+jwt";
    private static final String PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE =
            "swiyu-protected-verification-authorization-trust-statement+jwt";
    private static final String TP2_STATUS_LIST_URI =
            "https://mockserver:1080/api/v1/statuslist/tp2-trust-statements.jwt";

    @Test
    @XrayTest(
            key = "EIDOMNI-981",
            summary = "Request object contains verifier_info with verifier trust statements",
            description = """
                    This test validates that the OID4VP request object includes verifier TP2 trust
                    statements and that each appended verifier_info entry follows the required format,
                    {"format":"jwt","data":<jwt>}, without credential_ids.
                    This is the current end-to-end verifier-side TP2 trust-info shape check.
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This TP2 verifier flow relies on trust-registry-based request object enrichment."
    )
    void tenantVerifierRequestObject_whenTp2Enabled_thenVerifierInfoContainsIdTsPvaTsVqPs() {
        replaceVerifierTrustStatementRoutesWithSuccessfulResponses(CACHED_TRUST_STATEMENT_LIFETIME);
        final String verifierDid = "did:example:verifier-" + UUID.randomUUID();
        try {
            final var verificationRequest = verifierManager
                    .verificationRequest()
                    .withUniversityDCQL()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .jwtSecure();

            verificationRequest.getRequest().setConfigurationOverride(new ConfigurationOverrideDto().verifierDid(verifierDid));

            final ManagementResponse managementResponse = verificationRequest.createManagementResponse();

            final String firstRequestObject = wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            );
            final JsonNode firstVerifierInfo = verifierInfo(firstRequestObject);

            assertThat(firstVerifierInfo.isArray())
                    .as("verifier_info must be an array")
                    .isTrue();
            assertThat(firstVerifierInfo)
                    .as("TP2 verifier request info must at least include idTS and pvaTS")
                    .hasSizeGreaterThanOrEqualTo(2);

            final Set<String> firstTrustStatementTypes = statementTypes(firstVerifierInfo);
            assertThat(firstTrustStatementTypes)
                    .as("Verifier request-info must expose idTS and pvaTS")
                    .contains(IDENTITY_TRUST_STATEMENT_TYPE, PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE);
            assertVerifierInfoEntries(firstVerifierInfo);

            final String secondRequestObject = wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            );
            assertThat(verifierInfo(secondRequestObject))
                    .as("Verifier-info should be returned again")
                    .isEqualTo(firstVerifierInfo);
        } finally {
            restoreDefaultVerifierTrustStatementRoutes();
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-983",
            summary = "Cached verifier idTS and pvaTS are refreshed after exp-based TTL expiry",
            description = """
                    This test validates verifier request-object TP2 cache behavior.
                    It verifies short-lived idTS and pvaTS are served from cache until expiry and are
                    re-fetched with fresh JWTs after expiration.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This TP2 verifier flow relies on trust-registry-based request object enrichment."
    )
    void tenantVerifierRequestObject_whenTrustStatementExpReached_thenRefetchesFromTms() {
        replaceVerifierTrustStatementRoutesWithSuccessfulResponses(SHORT_TRUST_STATEMENT_LIFETIME);
        final String verifierDid = "did:example:verifier-" + UUID.randomUUID();
        try {
            final var verificationRequest = verifierManager
                    .verificationRequest()
                    .withUniversityDCQL()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .jwtSecure();

            verificationRequest.getRequest().setConfigurationOverride(new ConfigurationOverrideDto().verifierDid(verifierDid));

            final ManagementResponse managementResponse = verificationRequest.createManagementResponse();

            final String firstRequestObject = wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            );
            final JsonNode firstVerifierInfo = verifierInfo(firstRequestObject);

            final String firstIdTs = firstVerifierInfoEntry(firstVerifierInfo, IDENTITY_TRUST_STATEMENT_TYPE);
            final String firstPvaTs = firstVerifierInfoEntry(
                    firstVerifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE
            );

            assertThat(firstIdTs).as("idTS must be present before expiry").isNotBlank();
            assertThat(firstPvaTs).as("pvaTS must be present before expiry").isNotBlank();

            awaitTrustStatementsExpired(firstIdTs, firstPvaTs);

            final String secondRequestObject = wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            );
            final JsonNode secondVerifierInfo = verifierInfo(secondRequestObject);
            final String secondIdTs = firstVerifierInfoEntry(
                    secondVerifierInfo,
                    IDENTITY_TRUST_STATEMENT_TYPE
            );
            final String secondPvaTs = firstVerifierInfoEntry(
                    secondVerifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE
            );

            assertThat(firstIdTs)
                    .as("New idTS must be fetched after TTL expiry")
                    .isNotEqualTo(secondIdTs);
            assertThat(firstPvaTs)
                    .as("New pvaTS must be fetched after TTL expiry")
                    .isNotEqualTo(secondPvaTs);
        } finally {
            restoreDefaultVerifierTrustStatementRoutes();
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-984",
            summary = "Verifier request object can be used in a successful wallet verification",
            description = """
                    This test validates the full TP2 trust-statement-enabled OID4VP flow.
                    A holder gets a credential, the wallet fetches the signed request object, and
                    submits a matching presentation token. The verification must complete with SUCCESS.
                    """
    )
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This TP2 verifier flow relies on trust-registry-based request object enrichment."
    )
    void tenantVerifierSubmission_whenTp2TrustInfoPresent_thenVerificationSucceeds() {
        replaceVerifierTrustStatementRoutesWithSuccessfulResponses(CACHED_TRUST_STATEMENT_LIFETIME);

        try {
            final var issuedCredential = issuerManager.createCredentialOffer(
                    CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                    CredentialSubjectFixtures.completeEmployeeProfile()
            );
            final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(issuedCredential.getOfferDeeplink()));

            final String verifierDid = "did:example:verifier-full-flow-" + UUID.randomUUID();
            final var verificationRequest = verifierManager
                    .verificationRequest()
                    .withUniversityDCQL()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .jwtSecure();

            verificationRequest.getRequest().setConfigurationOverride(new ConfigurationOverrideDto().verifierDid(verifierDid));
            final ManagementResponse managementResponse = verificationRequest.createManagementResponse();

            final String requestObjectJwt = wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            );
            final JsonNode verifierInfo = verifierInfo(requestObjectJwt);
            final Set<String> verifierInfoTypes = statementTypes(verifierInfo);

            assertThat(verifierInfoTypes)
                    .as("TP2 verifier request object should contain idTS and pvaTS entries")
                    .contains(IDENTITY_TRUST_STATEMENT_TYPE, PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE);
            assertVerifierInfoEntries(verifierInfo);

            final RequestObject requestObject = parseSignedVerificationRequestObject(requestObjectJwt);
            final String presentation = batchEntry.createPresentationForSdJwtIndex(0, requestObject);
            wallet.respondToVerification(requestObject, presentation);

            verifierManager.verifyState(managementResponse.getId(), VerificationStatus.SUCCESS);
        } finally {
            restoreDefaultVerifierTrustStatementRoutes();
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "E2E-TP2-04: Policy validation rejects missing accepted issuer DIDs and trust anchors",
            description = """
                    This test validates that verifier request creation is rejected when neither acceptedIssuerDids
                    nor trustAnchors are provided. The API must return a 400 response with an explicit
                    validation error.
                    """
    )
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This TP2 verifier flow relies on trust-registry-based request object enrichment."
    )
    void tenantVerifierManagement_whenPolicyNotConfigured_thenRequestIsRejected() {
        final var verificationRequest = verifierManager
                .verificationRequest()
                .withUniversityDCQL()
                .jwtSecure();

        final HttpClientErrorException.BadRequest ex = assertThrows(
                HttpClientErrorException.BadRequest.class,
                verificationRequest::createManagementResponse
        );

        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasErrorDescription("Either acceptedIssuerDids or trustAnchors must be set and cannot be empty.");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "E2E-TP2-05: Transient TMS outage does not permanently block request-object fetches",
            description = """
                    This test validates that a temporary Trust Registry outage only affects one request-object fetch
                    attempt. The first fetch fails, and a second fetch immediately after retries and succeeds
                    with active verifier_info trust statements.
                    """
    )
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This TP2 verifier flow relies on trust-registry-based request object enrichment."
    )
    void tenantVerifierRequestObject_whenTmsTransientOutage_thenRecoversOnRetry() {
        replaceVerifierTrustStatementRoutesWithTransientErrorThenSuccessResponses(SHORT_TRUST_STATEMENT_LIFETIME);
        final String verifierDid = "did:example:verifier-transient-" + UUID.randomUUID();

        try {
            final var verificationRequest = verifierManager
                    .verificationRequest()
                    .withUniversityDCQL()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .jwtSecure();

            verificationRequest.getRequest().setConfigurationOverride(new ConfigurationOverrideDto().verifierDid(verifierDid));
            final ManagementResponse managementResponse = verificationRequest.createManagementResponse();

            final HttpStatusCodeException firstFailure = assertThrows(
                    HttpStatusCodeException.class,
                    () -> wallet.getVerificationDetailSigned(managementResponse.getVerificationDeeplink())
            );

            assertThat(firstFailure.getStatusCode().isError())
                    .as("Transient TMS outage should fail the first request-object fetch")
                    .isTrue();
            assertThat(firstFailure.getStatusCode().value())
                    .as("Transient outage must be a temporary error")
                    .isEqualTo(503);
            assertThat(firstFailure.getResponseBodyAsString())
                    .as("Transient outage should return explicit temporary error content")
                    .contains("temporary");

            final String secondRequestObject = wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            );
            final JsonNode secondVerifierInfo = verifierInfo(secondRequestObject);
            assertThat(secondVerifierInfo.isArray())
                    .as("Recovery fetch must include verifier_info payload")
                    .isTrue();
            final Set<String> statementTypes = statementTypes(secondVerifierInfo);
            assertThat(statementTypes)
                    .contains(IDENTITY_TRUST_STATEMENT_TYPE, PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE);
            assertThat(secondVerifierInfo).hasSizeGreaterThanOrEqualTo(2);
            assertVerifierInfoEntries(secondVerifierInfo);
        } finally {
            restoreDefaultVerifierTrustStatementRoutes();
        }
    }

    private JsonNode verifierInfo(String requestObjectJwt) {
        return JwtSupport.decodePayloadToJsonNode(requestObjectJwt).path("verifier_info");
    }

    private RequestObject parseSignedVerificationRequestObject(final String signedRequestObjectJwt) {
        try {
            return OBJECT_MAPPER.readValue(JwtSupport.decodePayload(signedRequestObjectJwt), RequestObject.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to parse signed verification request object", e);
        }
    }

    private void assertVerifierInfoEntries(JsonNode verifierInfo) {
        for (JsonNode entry : verifierInfo) {
            assertThat(entry.path("format").asText())
                    .as("verifier_info entries must have format 'jwt'")
                    .isEqualTo("jwt");
            assertThat(entry.path("credential_ids").isMissingNode())
                    .as("verifier_info entries must not have credential_ids")
                    .isTrue();
            final String statement = entry.path("data").asText();
            assertThat(statement)
                    .as("verifier_info data must be a non-empty JWT")
                    .isNotBlank();
            assertThat(statement.split("\\.").length)
                    .as("verifier_info data must be a compact JWT")
                    .isEqualTo(3);
            assertThat(statementType(statement))
                    .as("verifier_info entry must have a trust-statement JWT typ")
                    .isNotBlank();
        }
    }

    private Set<String> statementTypes(JsonNode verifierInfo) {
        return StreamSupport.stream(verifierInfo.spliterator(), false)
                .map(node -> statementType(node.path("data").asText()))
                .collect(Collectors.toSet());
    }

    private String firstVerifierInfoEntry(JsonNode verifierInfo, String expectedType) {
        return StreamSupport.stream(verifierInfo.spliterator(), false)
                .filter(node -> expectedType.equals(statementType(node.path("data").asText())))
                .map(node -> node.path("data").asText())
                .findFirst()
                .orElse("");
    }

    private String statementType(String statementJwt) {
        final JOSEObjectType type = JwtSupport.parse(statementJwt)
                .getHeader()
                .getType();
        return type == null ? "" : type.getType();
    }

    private void replaceVerifierTrustStatementRoutesWithSuccessfulResponses(Duration lifetime) {
        clearVerifierTrustStatementRoutes();

        mockServerClient.when(
                        request()
                                .withMethod("GET")
                                .withPath(IDENTITY_TRUST_STATEMENT_PATH + "/.+"),
                        Times.unlimited(),
                        TimeToLive.unlimited(),
                        100
                )
                .respond(httpRequest -> response()
                        .withStatusCode(200)
                        .withHeader("Content-Type", "application/jwt")
                        .withBody(buildIdentityTrustStatement(
                                extractLastPathSegment(httpRequest),
                                lifetime
                        )));

        mockServerClient.when(
                        request()
                                .withMethod("GET")
                                .withPath(PROTECTED_VERIFICATION_AUTHORIZATION_PATH + "/?"),
                        Times.unlimited(),
                        TimeToLive.unlimited(),
                        100
                )
                .respond(httpRequest -> response()
                        .withStatusCode(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(protectedVerificationAuthorizationResponse(
                                httpRequest.getFirstQueryStringParameter("sub"),
                                lifetime
                        )));
    }

    private void replaceVerifierTrustStatementRoutesWithTransientErrorThenSuccessResponses(Duration lifetime) {
        clearVerifierTrustStatementRoutes();

        final AtomicInteger idTsAttempts = new AtomicInteger();
        final AtomicInteger pvaTsAttempts = new AtomicInteger();

        mockServerClient.when(
                        request()
                                .withMethod("GET")
                                .withPath(IDENTITY_TRUST_STATEMENT_PATH + "/.+"),
                        Times.unlimited(),
                        TimeToLive.unlimited(),
                        100
                )
                .respond(httpRequest -> {
                    if (idTsAttempts.getAndIncrement() == 0) {
                        return response()
                                .withStatusCode(503)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"error\":\"temporary idTS fetch failure\"}");
                    }

                    return response()
                            .withStatusCode(200)
                            .withHeader("Content-Type", "application/jwt")
                            .withBody(buildIdentityTrustStatement(
                                    extractLastPathSegment(httpRequest),
                                    lifetime
                            ));
                });

        mockServerClient.when(
                        request()
                                .withMethod("GET")
                                .withPath(PROTECTED_VERIFICATION_AUTHORIZATION_PATH + "/?"),
                        Times.unlimited(),
                        TimeToLive.unlimited(),
                        100
                )
                .respond(httpRequest -> {
                    if (pvaTsAttempts.getAndIncrement() == 0) {
                        return response()
                                .withStatusCode(503)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"error\":\"temporary pvaTS fetch failure\"}");
                    }

                    return response()
                            .withStatusCode(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody(protectedVerificationAuthorizationResponse(
                                    httpRequest.getFirstQueryStringParameter("sub"),
                                    lifetime
                            ));
                });
    }

    private void restoreDefaultVerifierTrustStatementRoutes() {
        clearVerifierTrustStatementRoutes();
        Tp2TrustRegistryMockServerConfigurer.registerRoutes(
                mockServerClient,
                issuerConfig,
                trustConfig,
                OBJECT_MAPPER
        );
    }

    private void clearVerifierTrustStatementRoutes() {
        mockServerClient.clear(
                request().withMethod("GET").withPath(IDENTITY_TRUST_STATEMENT_PATH + "/.+"),
                ClearType.EXPECTATIONS
        );
        mockServerClient.clear(
                request().withMethod("GET").withPath(PROTECTED_VERIFICATION_AUTHORIZATION_PATH + "/?"),
                ClearType.EXPECTATIONS
        );
    }

    private String buildIdentityTrustStatement(String subject, Duration lifetime) {
        return signTrustStatement(
                IDENTITY_TRUST_STATEMENT_TYPE,
                claimsBuilder(subject, lifetime)
                        .claim("status", statusListClaim(0))
                        .claim("entity_name", "Mock TP2 Verifier")
                        .claim("is_state_actor", true)
                        .claim("registry_ids", List.of(Map.of("type", "UID", "value", "CHE-123.456.789")))
                        .build()
        );
    }

    private String buildProtectedVerificationAuthorizationTrustStatement(String subject, Duration lifetime) {
        return signTrustStatement(
                PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE,
                claimsBuilder(subject, lifetime)
                        .claim("status", statusListClaim(0))
                        .claim("jti", UUID.randomUUID().toString())
                        .claim("authorized_fields", List.of("personal_administrative_number"))
                        .build()
        );
    }

    private String protectedVerificationAuthorizationResponse(String subject, Duration lifetime) {
        try {
            final List<String> content = List.of(
                    buildProtectedVerificationAuthorizationTrustStatement(subject, lifetime)
            );
            return OBJECT_MAPPER.writeValueAsString(Map.of(
                    "content", content,
                    "page", Map.of(
                            "size", content.size(),
                            "number", 0,
                            "totalPages", 1,
                            "totalElements", content.size()
                    )
            ));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Cannot serialize mock pvaTS response", e);
        }
    }

    private JWTClaimsSet.Builder claimsBuilder(String subject, Duration lifetime) {
        final Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(trustConfig.getTrustDid())
                .subject(subject)
                .issueTime(java.util.Date.from(now))
                .notBeforeTime(java.util.Date.from(now))
                .expirationTime(java.util.Date.from(now.plus(lifetime)));
    }

    private Map<String, Object> statusListClaim(int index) {
        return Map.of(
                "status_list", Map.of(
                        "idx", index,
                        "uri", TP2_STATUS_LIST_URI
                )
        );
    }

    private String signTrustStatement(String type, JWTClaimsSet claimsSet) {
        try {
            final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(trustConfig.getTrustAssertKeyId())
                    .type(new JOSEObjectType(type))
                    .customParam("profile_version", TP2_PROFILE_VERSION)
                    .build();

            final SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            final JWK trustJwk = JWK.parseFromPEMEncodedObjects(trustConfig.getTrustAssertKeyPemString());
            signedJWT.sign(new ECDSASigner(trustJwk.toECKey()));
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot sign mock TP2 trust statement", e);
        }
    }

    private void awaitTrustStatementsExpired(String idTs, String pvaTs) {
        final Instant earliestExpiry = earliestExpiry(idTs, pvaTs);
        await()
                .pollInterval(Duration.ofMillis(100))
                .atMost(SHORT_TRUST_STATEMENT_LIFETIME.plusSeconds(3))
                .until(() -> Instant.now().isAfter(earliestExpiry.plusSeconds(1)));
    }

    private Instant earliestExpiry(String... jwts) {
        return List.of(jwts).stream()
                .map(this::expiresAt)
                .min(Instant::compareTo)
                .orElseThrow(() -> new IllegalStateException("No JWT expiry found"));
    }

    private Instant expiresAt(String jwt) {
        try {
            return SignedJWT.parse(jwt).getJWTClaimsSet().getExpirationTime().toInstant();
        } catch (ParseException e) {
            throw new IllegalStateException("Cannot parse mock trust statement expiry", e);
        }
    }

    private String extractLastPathSegment(HttpRequest httpRequest) {
        final String path = httpRequest.getPath().getValue();
        final int lastSlash = path.lastIndexOf('/');
        if (lastSlash < 0 || lastSlash == path.length() - 1) {
            return path;
        }
        return java.net.URLDecoder.decode(path.substring(lastSlash + 1), java.nio.charset.StandardCharsets.UTF_8);
    }
}
