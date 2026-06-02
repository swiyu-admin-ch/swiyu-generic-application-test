package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.gen.verifier.model.ConfigurationOverrideDto;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlQueryDto;
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
import com.fasterxml.jackson.databind.DeserializationFeature;
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
import org.springframework.http.MediaType;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
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

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .findAndRegisterModules()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    private static final Duration CACHED_TRUST_STATEMENT_LIFETIME = Duration.ofMinutes(5);
    private static final Duration SHORT_TRUST_STATEMENT_LIFETIME = Duration.ofSeconds(5);
    private static final String IDENTITY_TRUST_STATEMENT_PATH = "/api/v2/identity-trust-statement";
    private static final String PROTECTED_VERIFICATION_AUTHORIZATION_PATH =
            "/api/v2/protected-verification-authorization-trust-statement";
    private static final String VERIFICATION_QUERY_PUBLIC_STATEMENT_PATH =
            "/api/v2/verification-query-public-statement";
    private static final String VQPS_SUBMISSION_PATH = "/api/v1/trust/vqps-submissions";
    private static final String TP2_PROFILE_VERSION = "swiss-profile-trust:1.0.0";
    private static final String IDENTITY_TRUST_STATEMENT_TYPE = "swiyu-identity-trust-statement+jwt";
    private static final String PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE =
            "swiyu-protected-verification-authorization-trust-statement+jwt";
    private static final String VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE =
            "swiyu-verification-query-public-statement+jwt";
    private static final String TP2_STATUS_LIST_URI =
            "https://mockserver:1080/api/v1/statuslist/tp2-trust-statements.jwt";
    private static final String VERIFICATION_QUERY_SCOPE = "ch.swiyu.tp2.employment.presentation";
    private static final String PROTECTED_VCT = "http://default-issuer-url.admin.ch/oid4vci/vct/my-vct-v01";

    private final Map<String, String> vqPsBySubject = new ConcurrentHashMap<>();
    private final Map<String, String> vqPsByJti = new ConcurrentHashMap<>();

    @Test
    @XrayTest(
            key = "EIDOMNI-981",
            summary = "Request object contains verifier_info with verifier idTS, pvaTS, and vqPS",
            description = """
                    This test validates that the OID4VP request object includes the verifier TP2 idTS,
                    pvaTS, and vqPS trust statements and that each appended verifier_info entry follows the
                    required format,
                    {"format":"jwt","data":<jwt>}, without credential_ids.
                    This is the verifier-side TP2 trust-info shape check required for wallet Trust-UI.
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This TP2 verifier flow relies on trust-registry-based request object enrichment."
    )
    void tenantVerifierRequestObject_whenTp2Enabled_thenVerifierInfoContainsIdTsPvaTsVqPs() {
        replaceVerifierTrustStatementRoutesWithSuccessfulResponses(CACHED_TRUST_STATEMENT_LIFETIME);
        final String verifierDid = configuredVerifierDid();
        final String scope = uniqueScope("request-info");
        try {
            final ManagementResponse managementResponse = createVerificationWithPurpose(scope);

            final String firstRequestObject = wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            );
            final JsonNode firstVerifierInfo = verifierInfo(firstRequestObject);

            assertThat(firstVerifierInfo.isArray())
                    .as("verifier_info must be an array")
                    .isTrue();
            assertThat(firstVerifierInfo)
                    .as("TP2 verifier request info must include idTS, pvaTS, and vqPS")
                    .hasSizeGreaterThanOrEqualTo(3);

            final Set<String> firstTrustStatementTypes = statementTypes(firstVerifierInfo);
            assertThat(firstTrustStatementTypes)
                    .as("Verifier request-info must expose idTS, pvaTS, and the verification query public statement")
                    .contains(
                            IDENTITY_TRUST_STATEMENT_TYPE,
                            PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE,
                            VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE
                    );
            assertVerificationQueryPublicStatement(firstVerifierInfo, verifierDid);
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
            key = "EIDOMNI-XXX",
            summary = "Verifier embeds vqPS in verifier_info",
            description = """
                    This test validates that the OID4VP request object embeds the Verification Query Public
                    Statement in verifier_info so the wallet can establish public transparency for the
                    the intended verification scope.
                    """
    )
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This TP2 verifier flow relies on trust-registry-based request object enrichment."
    )
    void tenantVerifierRequestObject_whenTp2Enabled_thenVerifierInfoContainsVqPs() {
        replaceVerifierTrustStatementRoutesWithSuccessfulResponses(CACHED_TRUST_STATEMENT_LIFETIME);
        final String verifierDid = configuredVerifierDid();
        final String scope = uniqueScope("vqps");

        try {
            final ManagementResponse managementResponse = createVerificationWithPurpose(scope);

            final String requestObjectJwt = wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            );
            final JsonNode verifierInfo = verifierInfo(requestObjectJwt);
            final Set<String> verifierInfoTypes = statementTypes(verifierInfo);

            assertThat(verifierInfoTypes)
                    .as("verifier_info must contain all TP2 verifier statements")
                    .contains(
                            IDENTITY_TRUST_STATEMENT_TYPE,
                            PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE,
                            VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE
                    );
            assertThat(verifierInfoEntryCount(verifierInfo, VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE))
                    .as("verifier_info must contain exactly one vqPS")
                    .isOne();
            assertVerificationQueryPublicStatement(verifierInfo, verifierDid);
            assertVerifierInfoEntries(verifierInfo);
        } finally {
            restoreDefaultVerifierTrustStatementRoutes();
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Verifier trust-statement cache is isolated by verifier DID",
            description = """
                    This test validates that cached idTS and pvaTS entries are scoped to the verifier DID.
                    A request object created for a second verifier DID must not reuse trust statements that were
                    fetched for a previous verifier DID.
                    """
    )
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This TP2 verifier flow relies on trust-registry-based request object enrichment."
    )
    void tenantVerifierRequestObject_whenVerifierDidChanges_thenTrustStatementCacheIsSubjectScoped() {
        replaceVerifierTrustStatementRoutesWithSuccessfulResponses(CACHED_TRUST_STATEMENT_LIFETIME);
        final String firstVerifierDid = "did:example:verifier-cache-a-" + UUID.randomUUID();
        final String secondVerifierDid = "did:example:verifier-cache-b-" + UUID.randomUUID();

        try {
            final var firstVerificationRequest = verifierManager
                    .verificationRequest()
                    .withUniversityDCQL()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .jwtSecure();
            firstVerificationRequest.getRequest()
                    .setConfigurationOverride(new ConfigurationOverrideDto().verifierDid(firstVerifierDid));
            final ManagementResponse firstManagementResponse = firstVerificationRequest.createManagementResponse();
            final JsonNode firstVerifierInfo = verifierInfo(wallet.getVerificationDetailSigned(
                    firstManagementResponse.getVerificationDeeplink()
            ));

            assertVerifierInfoStatementSubject(firstVerifierInfo, IDENTITY_TRUST_STATEMENT_TYPE, firstVerifierDid);
            assertVerifierInfoStatementSubject(
                    firstVerifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE,
                    firstVerifierDid
            );

            final String firstIdTs = firstVerifierInfoEntry(firstVerifierInfo, IDENTITY_TRUST_STATEMENT_TYPE);
            final String firstPvaTs = firstVerifierInfoEntry(
                    firstVerifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE
            );

            final var secondVerificationRequest = verifierManager
                    .verificationRequest()
                    .withUniversityDCQL()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .jwtSecure();
            secondVerificationRequest.getRequest()
                    .setConfigurationOverride(new ConfigurationOverrideDto().verifierDid(secondVerifierDid));
            final ManagementResponse secondManagementResponse = secondVerificationRequest.createManagementResponse();
            final JsonNode secondVerifierInfo = verifierInfo(wallet.getVerificationDetailSigned(
                    secondManagementResponse.getVerificationDeeplink()
            ));

            assertVerifierInfoStatementSubject(secondVerifierInfo, IDENTITY_TRUST_STATEMENT_TYPE, secondVerifierDid);
            assertVerifierInfoStatementSubject(
                    secondVerifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE,
                    secondVerifierDid
            );

            assertThat(firstIdTs)
                    .as("idTS cache must not be reused for a different verifier DID")
                    .isNotEqualTo(firstVerifierInfoEntry(secondVerifierInfo, IDENTITY_TRUST_STATEMENT_TYPE));
            assertThat(firstPvaTs)
                    .as("pvaTS cache must not be reused for a different verifier DID")
                    .isNotEqualTo(firstVerifierInfoEntry(
                            secondVerifierInfo,
                            PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE
                    ));
        } finally {
            restoreDefaultVerifierTrustStatementRoutes();
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Verifier registers vqPS on-the-fly for verification purpose",
            description = """
                    This test validates that the Business Verifier management API accepts a DCQL query with
                    verification_purpose transparency metadata, registers the query at the TMS as a vqPS,
                    and later embeds the published vqPS in the OID4VP request object.
                    """
    )
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This TP2 verifier flow validates the upcoming on-the-fly vqPS registration contract."
    )
    void tenantVerifierManagement_whenVerificationPurposeProvided_thenRegistersAndEmbedsOnTheFlyVqPs()
            throws JsonProcessingException {
        replaceVerifierTrustStatementRoutesWithSuccessfulResponses(CACHED_TRUST_STATEMENT_LIFETIME);
        clearVqPsRegistrationLog();
        final String verifierDid = configuredVerifierDid();
        final String scope = "com.example.age_verification." + UUID.randomUUID();
        final Map<String, Object> dcqlQuery = dcqlQueryPayload();

        try {
            final ManagementResponse managementResponse = createVerificationWithPurpose(
                    scope,
                    dcqlQuery
            );

            await().atMost(Duration.ofSeconds(5)).untilAsserted(() ->
                    assertThat(recordedVqPsRegistrationRequests())
                            .as("Verifier must register a vqPS at TMS during verification creation")
                            .hasSize(1)
            );

            final HttpRequest registrationRequest = recordedVqPsRegistrationRequests()[0];
            assertVqPsRegistrationRequest(registrationRequest, verifierDid, scope);

            final String requestObjectJwt = wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            );
            final JsonNode requestObjectPayload = JwtSupport.decodePayloadToJsonNode(requestObjectJwt);
            assertThat(requestObjectPayload.path("scope").asText())
                    .as("Authorization Request scope must match the vqPS registered scope")
                    .isEqualTo(scope);

            final JsonNode verifierInfo = requestObjectPayload.path("verifier_info");
            final String vqPs = firstVerifierInfoEntry(verifierInfo, VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE);
            assertThat(vqPs)
                    .as("Request object must include the TMS-published vqPS")
                    .isNotBlank();
            assertThat(statementPayload(vqPs).path("request").path("scope").asText())
                    .as("Embedded vqPS scope must match the Authorization Request scope")
                    .isEqualTo(scope);
            assertThat(statementPayload(vqPs).path("request").path("query"))
                    .as("Embedded vqPS query must match the management DCQL query")
                    .isEqualTo(OBJECT_MAPPER.valueToTree(dcqlQuery));
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
        final String scope = uniqueScope("ttl");
        try {
            final ManagementResponse managementResponse = createVerificationWithPurpose(scope);

            final String firstRequestObject = wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            );
            final JsonNode firstVerifierInfo = verifierInfo(firstRequestObject);

            final String firstIdTs = firstVerifierInfoEntry(firstVerifierInfo, IDENTITY_TRUST_STATEMENT_TYPE);
            final String firstPvaTs = firstVerifierInfoEntry(
                    firstVerifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE
            );
            final String firstVqPs = firstVerifierInfoEntry(
                    firstVerifierInfo,
                    VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE
            );

            assertThat(firstIdTs).as("idTS must be present before expiry").isNotBlank();
            assertThat(firstPvaTs).as("pvaTS must be present before expiry").isNotBlank();
            assertThat(firstVqPs).as("vqPS must be present before idTS/pvaTS expiry").isNotBlank();

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
            final String secondVqPs = firstVerifierInfoEntry(
                    secondVerifierInfo,
                    VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE
            );

            assertThat(firstIdTs)
                    .as("New idTS must be fetched after TTL expiry")
                    .isNotEqualTo(secondIdTs);
            assertThat(firstPvaTs)
                    .as("New pvaTS must be fetched after TTL expiry")
                    .isNotEqualTo(secondPvaTs);
            assertThat(secondVqPs)
                    .as("vqPS is tied to the verification context and must remain available after idTS/pvaTS refresh")
                    .isEqualTo(firstVqPs);
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

            final String verifierDid = configuredVerifierDid();
            final String scope = uniqueScope("full-flow");
            final ManagementResponse managementResponse = createVerificationWithPurpose(scope);

            final String requestObjectJwt = wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            );
            final JsonNode verifierInfo = verifierInfo(requestObjectJwt);
            final Set<String> verifierInfoTypes = statementTypes(verifierInfo);

            assertThat(verifierInfoTypes)
                    .as("TP2 verifier request object should contain idTS, pvaTS, and vqPS entries")
                    .contains(
                            IDENTITY_TRUST_STATEMENT_TYPE,
                            PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE,
                            VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE
                    );
            assertVerificationQueryPublicStatement(verifierInfo, verifierDid);
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
            summary = "Verifier skips request-object idTS enrichment when idTS signature is invalid",
            description = """
                    This test validates the pre-injection trust-statement validation boundary.
                    When the TMS returns an idTS whose signature cannot be validated against the trust issuer DID,
                    the Verifier must skip the invalid idTS and continue request-object generation with the valid pvaTS.
                    """
    )
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This TP2 verifier flow relies on trust-registry-based request object enrichment."
    )
    void tenantVerifierRequestObject_whenIdentityTrustStatementSignatureInvalid_thenIdTsIsSkipped() {
        replaceVerifierTrustStatementRoutesWithInvalidIdentitySignature(CACHED_TRUST_STATEMENT_LIFETIME);
        final String verifierDid = configuredVerifierDid();
        final String scope = uniqueScope("invalid-idts");

        try {
            final ManagementResponse managementResponse = createVerificationWithPurpose(scope);

            final String requestObjectJwt = wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            );
            final JsonNode verifierInfo = verifierInfo(requestObjectJwt);
            final Set<String> statementTypes = statementTypes(verifierInfo);

            assertThat(statementTypes)
                    .as("Invalid idTS signatures are skipped during request-object enrichment")
                    .doesNotContain(IDENTITY_TRUST_STATEMENT_TYPE);
            assertThat(statementTypes)
                    .as("Valid pvaTS enrichment should still be present")
                    .contains(PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE);
            assertThat(statementTypes)
                    .as("Valid vqPS enrichment should still be present")
                    .contains(VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE);
            assertVerificationQueryPublicStatement(verifierInfo, verifierDid);
            assertVerifierInfoEntries(verifierInfo);
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
                .hasErrorDescription(
                        "createVerificationManagementDto: Either acceptedIssuerDids or trustAnchors "
                                + "must be set and cannot be empty."
                );
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "E2E-TP2-05: Transient TMS outage omits verifier_info during negative cache window",
            description = """
                    This test validates that a temporary Trust Registry outage does not fail request-object fetches.
                    The Verifier gracefully returns a signed request object without verifier_info and immediately
                    repeated fetches remain without verifier_info during the short negative-cache window.
                    """
    )
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This TP2 verifier flow relies on trust-registry-based request object enrichment."
    )
    void tenantVerifierRequestObject_whenTmsTransientOutage_thenVerifierInfoIsTemporarilyOmitted() {
        replaceVerifierTrustStatementRoutesWithTransientErrorThenSuccessResponses(SHORT_TRUST_STATEMENT_LIFETIME);
        final String verifierDid = "did:example:verifier-transient-" + UUID.randomUUID();

        try {
            final var verificationRequest = verifierManager
                    .verificationRequest()
                    .withUniversityDCQL()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .jwtSecure();

            verificationRequest.getRequest()
                    .setConfigurationOverride(new ConfigurationOverrideDto().verifierDid(verifierDid));
            final ManagementResponse managementResponse = verificationRequest.createManagementResponse();

            final String firstRequestObject = wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            );
            assertVerifierInfoAbsent(verifierInfo(firstRequestObject));

            final String repeatedRequestObject = wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            );
            assertVerifierInfoAbsent(verifierInfo(repeatedRequestObject));
        } finally {
            restoreDefaultVerifierTrustStatementRoutes();
        }
    }

    private JsonNode verifierInfo(String requestObjectJwt) {
        return JwtSupport.decodePayloadToJsonNode(requestObjectJwt).path("verifier_info");
    }

    private String configuredVerifierDid() {
        return verifierConfig.getVerifierDid();
    }

    private String uniqueScope(String scenario) {
        return "ch.swiyu.tp2." + scenario + "." + UUID.randomUUID();
    }

    private String purposeDescription(String scope) {
        return "Checks that the holder satisfies the requested policy for scope " + scope + ".";
    }

    private ManagementResponse createVerificationWithPurpose(String scope) {
        return createVerificationWithPurpose(scope, dcqlQueryPayload());
    }

    private ManagementResponse createVerificationWithPurpose(
            String scope,
            Map<String, Object> dcqlQuery) {
        final Map<String, Object> request = Map.of(
                "accepted_issuer_dids", List.of(issuerConfig.getIssuerDid()),
                "jwt_secured_authorization_request", true,
                "response_mode", "direct_post",
                "verification_purpose", Map.of(
                        "scope", scope,
                        "purpose_name", Map.of(
                                "en", "Age verification",
                                "de-CH", "Altersverifikation"
                        ),
                        "purpose_description", Map.of(
                                "en", purposeDescription(scope),
                                "de-CH", purposeDescription(scope)
                        )
                ),
                "dcql_query", dcqlQuery
        );

        return restClient.post()
                .uri(verifierManagementUrl())
                .contentType(MediaType.APPLICATION_JSON)
                .body(request)
                .retrieve()
                .body(ManagementResponse.class);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> dcqlQueryPayload() {
        return OBJECT_MAPPER.convertValue(
                ch.admin.bj.swiyu.swiyu_test_wallet.support.TestPresentationDefinitions.universityPresentationDCQL(),
                Map.class
        );
    }

    private String verifierManagementUrl() {
        return "http://%s:%d/management/api/verifications".formatted(
                verifierContainer.getHost(),
                verifierContainer.getMappedPort(8080)
        );
    }

    private HttpRequest[] recordedVqPsRegistrationRequests() {
        return mockServerClient.retrieveRecordedRequests(
                request().withMethod("POST").withPath(VQPS_SUBMISSION_PATH + "/?")
        );
    }

    private void clearVqPsRegistrationLog() {
        mockServerClient.clear(
                request().withMethod("POST").withPath(VQPS_SUBMISSION_PATH + "/?"),
                ClearType.LOG
        );
    }

    private void assertVqPsRegistrationRequest(HttpRequest registrationRequest, String verifierDid, String scope)
            throws JsonProcessingException {
        final JsonNode body = OBJECT_MAPPER.readTree(registrationRequest.getBodyAsString());
        assertThat(body.path("sub").asText())
                .as("TMS vqPS registration subject must be the verifier DID")
                .isEqualTo(verifierDid);

        final JsonNode request = body.has("request") ? body.path("request") : body;
        assertThat(request.path("type").asText("DCQL"))
                .as("TMS vqPS registration request.type must be DCQL")
                .isEqualTo("DCQL");
        assertThat(request.path("scope").asText())
                .as("TMS vqPS registration scope must match verification_purpose.scope")
                .isEqualTo(scope);
        assertThat(request.path("query").path("credentials"))
                .as("TMS vqPS registration must contain the DCQL credentials query")
                .isNotEmpty();

        assertThat(hasLocalizedValue(body, "purpose_name", "en", "Age verification"))
                .as("TMS vqPS registration must include localized purpose_name metadata")
                .isTrue();
        assertThat(hasLocalizedValue(
                body,
                "purpose_description",
                "en",
                purposeDescription(scope)
        ))
                .as("TMS vqPS registration must include localized purpose_description metadata")
                .isTrue();
    }

    private boolean hasLocalizedValue(JsonNode body, String claimName, String locale, String expectedValue) {
        return expectedValue.equals(body.path(claimName).path(locale).asText(null))
                || expectedValue.equals(body.path(claimName + "#" + locale).asText(null));
    }

    private RequestObject parseSignedVerificationRequestObject(final String signedRequestObjectJwt) {
        try {
            RequestObject requestObject = OBJECT_MAPPER.readValue(
                    JwtSupport.decodePayload(signedRequestObjectJwt),
                    RequestObject.class
            );
            if (requestObject.getDcqlQuery() == null) {
                hydrateDcqlQueryFromVqPs(requestObject, signedRequestObjectJwt);
            }
            return requestObject;
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to parse signed verification request object", e);
        }
    }

    private void hydrateDcqlQueryFromVqPs(RequestObject requestObject, String signedRequestObjectJwt)
            throws JsonProcessingException {
        final String vqPs = firstVerifierInfoEntry(
                verifierInfo(signedRequestObjectJwt),
                VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE
        );
        if (vqPs.isBlank()) {
            return;
        }
        requestObject.setDcqlQuery(OBJECT_MAPPER.treeToValue(
                statementPayload(vqPs).path("request").path("query"),
                DcqlQueryDto.class
        ));
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
            assertThat(JWSAlgorithm.ES256.equals(JwtSupport.parse(statement).getHeader().getAlgorithm()))
                    .as("verifier_info trust statements must be ES256 signed")
                    .isTrue();
            assertThat(statementProfileVersion(statement))
                    .as("verifier_info trust statements must use the active Swiss TP2 profile")
                    .isEqualTo(TP2_PROFILE_VERSION);
        }
    }

    private void assertVerifierInfoStatementSubject(
            JsonNode verifierInfo,
            String expectedType,
            String expectedSubject) {
        final String statement = firstVerifierInfoEntry(verifierInfo, expectedType);
        assertThat(statement)
                .as("verifier_info must contain " + expectedType)
                .isNotBlank();
        assertThat(statementPayload(statement).path("sub").asText())
                .as(expectedType + " subject must match the verifier DID")
                .isEqualTo(expectedSubject);
    }

    private void assertVerificationQueryPublicStatement(JsonNode verifierInfo, String expectedSubject) {
        final String vqPs = firstVerifierInfoEntry(verifierInfo, VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE);
        assertThat(vqPs)
                .as("verifier_info must contain a vqPS")
                .isNotBlank();
        assertThat(verifierInfoEntryCount(verifierInfo, VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE))
                .as("verifier_info must contain exactly one vqPS")
                .isOne();
        assertThat(statementPayload(vqPs).path("sub").asText())
                .as("vqPS subject must match the verifier DID")
                .isEqualTo(expectedSubject);

        final JsonNode request = statementPayload(vqPs).path("request");
        assertThat(request.path("type").asText())
                .as("vqPS request.type must be DCQL")
                .isEqualTo("DCQL");
        assertThat(request.path("scope").asText())
                .as("vqPS request.scope must be present")
                .isNotBlank();

        final JsonNode credentials = request.path("query").path("credentials");
        assertThat(credentials.isArray())
                .as("vqPS request.query.credentials must be an array")
                .isTrue();
        assertThat(credentials)
                .as("vqPS request.query.credentials must not be empty")
                .isNotEmpty();

        for (JsonNode credential : credentials) {
            final JsonNode vctValues = credential.path("meta").path("vct_values");
            assertThat(vctValues.isArray())
                    .as("Each vqPS DCQL credential query must include meta.vct_values")
                    .isTrue();
            assertThat(vctValues)
                    .as("Each vqPS DCQL credential query must include a non-empty meta.vct_values array")
                    .isNotEmpty();
        }
    }

    private void assertVerifierInfoAbsent(JsonNode verifierInfo) {
        assertThat(verifierInfo.isMissingNode() || verifierInfo.isNull())
                .as("verifier_info must be omitted when no trust statements are available")
                .isTrue();
    }

    private Set<String> statementTypes(JsonNode verifierInfo) {
        return StreamSupport.stream(verifierInfo.spliterator(), false)
                .map(node -> statementType(node.path("data").asText()))
                .collect(Collectors.toSet());
    }

    private long verifierInfoEntryCount(JsonNode verifierInfo, String expectedType) {
        return StreamSupport.stream(verifierInfo.spliterator(), false)
                .filter(node -> expectedType.equals(statementType(node.path("data").asText())))
                .count();
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

    private JsonNode statementPayload(String statementJwt) {
        return JwtSupport.decodePayloadToJsonNode(statementJwt);
    }

    private Object statementProfileVersion(String statementJwt) {
        return JwtSupport.parse(statementJwt)
                .getHeader()
                .getCustomParam("profile_version");
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

        registerVerificationQueryPublicStatementRoutes(CACHED_TRUST_STATEMENT_LIFETIME);
    }

    private void replaceVerifierTrustStatementRoutesWithTransientErrorThenSuccessResponses(Duration lifetime) {
        clearVerifierTrustStatementRoutes();

        final AtomicInteger idTsAttempts = new AtomicInteger();
        final AtomicInteger pvaTsAttempts = new AtomicInteger();
        final AtomicInteger vqPsAttempts = new AtomicInteger();

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

        registerVerificationQueryPublicStatementRoutes(CACHED_TRUST_STATEMENT_LIFETIME, vqPsAttempts);
    }

    private void replaceVerifierTrustStatementRoutesWithInvalidIdentitySignature(Duration lifetime) {
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
                        .withBody(tamperJwtSignature(buildIdentityTrustStatement(
                                extractLastPathSegment(httpRequest),
                                lifetime
                        ))));

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

        registerVerificationQueryPublicStatementRoutes(CACHED_TRUST_STATEMENT_LIFETIME);
    }

    private void registerVerificationQueryPublicStatementRoutes(Duration lifetime) {
        registerVerificationQueryPublicStatementRoutes(lifetime, null);
    }

    private void registerVerificationQueryPublicStatementRoutes(
            Duration lifetime,
            AtomicInteger transientFailures) {
        mockServerClient.when(
                        request()
                                .withMethod("GET")
                                .withPath(VERIFICATION_QUERY_PUBLIC_STATEMENT_PATH + "/?"),
                        Times.unlimited(),
                        TimeToLive.unlimited(),
                        100
                )
                .respond(httpRequest -> {
                    if (transientFailures != null && transientFailures.getAndIncrement() == 0) {
                        return response()
                                .withStatusCode(503)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"error\":\"temporary vqPS fetch failure\"}");
                    }

                    return response()
                            .withStatusCode(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody(verificationQueryPublicStatementResponse(
                                    httpRequest.getFirstQueryStringParameter("sub"),
                                    lifetime
                            ));
                });

        mockServerClient.when(
                        request()
                                .withMethod("GET")
                                .withPath(VERIFICATION_QUERY_PUBLIC_STATEMENT_PATH + "/.+"),
                        Times.unlimited(),
                        TimeToLive.unlimited(),
                        100
                )
                .respond(httpRequest -> {
                    final String statement = vqPsByJti.get(extractLastPathSegment(httpRequest));
                    if (statement == null) {
                        return response()
                                .withStatusCode(404)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"error\":\"No vqPS found for jti\"}");
                    }

                    return response()
                            .withStatusCode(200)
                            .withHeader("Content-Type", "application/jwt")
                            .withBody(statement);
                });
    }

    private void restoreDefaultVerifierTrustStatementRoutes() {
        clearVerifierTrustStatementRoutes();
        Tp2TrustRegistryMockServerConfigurer.registerRoutes(
                mockServerClient,
                issuerConfig,
                verifierConfig,
                trustConfig,
                OBJECT_MAPPER
        );
    }

    private void clearVerifierTrustStatementRoutes() {
        vqPsBySubject.clear();
        vqPsByJti.clear();
        mockServerClient.clear(
                request().withMethod("GET").withPath(IDENTITY_TRUST_STATEMENT_PATH + "/.+"),
                ClearType.EXPECTATIONS
        );
        mockServerClient.clear(
                request().withMethod("GET").withPath(PROTECTED_VERIFICATION_AUTHORIZATION_PATH + "/?"),
                ClearType.EXPECTATIONS
        );
        mockServerClient.clear(
                request().withMethod("GET").withPath(VERIFICATION_QUERY_PUBLIC_STATEMENT_PATH + "/?"),
                ClearType.EXPECTATIONS
        );
        mockServerClient.clear(
                request().withMethod("GET").withPath(VERIFICATION_QUERY_PUBLIC_STATEMENT_PATH + "/.+"),
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

    private String buildVerificationQueryPublicStatement(String subject, String jti, Duration lifetime) {
        return signTrustStatement(
                VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE,
                claimsBuilder(subject, lifetime)
                        .jwtID(jti)
                        .claim("purpose_name", "Employment check")
                        .claim("purpose_name#en", "Employment check")
                        .claim("purpose_description", "Mock TP2 verification request used by application tests.")
                        .claim("purpose_description#en", "Mock TP2 verification request used by application tests.")
                        .claim("request", verificationQueryRequest())
                        .build()
        );
    }

    private String verificationQueryPublicStatementResponse(String subject, Duration lifetime) {
        try {
            final List<String> content = subject == null || subject.isBlank()
                    ? List.of()
                    : List.of(verificationQueryPublicStatementForSubject(subject, lifetime));

            return OBJECT_MAPPER.writeValueAsString(Map.of(
                    "content", content,
                    "page", Map.of(
                            "size", content.size(),
                            "number", 0,
                            "totalPages", content.isEmpty() ? 0 : 1,
                            "totalElements", content.size()
                    )
            ));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Cannot serialize mock vqPS response", e);
        }
    }

    private String verificationQueryPublicStatementForSubject(String subject, Duration lifetime) {
        return vqPsBySubject.computeIfAbsent(subject, requestedSubject -> {
            final String jti = UUID.randomUUID().toString();
            final String statement = buildVerificationQueryPublicStatement(requestedSubject, jti, lifetime);
            vqPsByJti.put(jti, statement);
            return statement;
        });
    }

    private Map<String, Object> verificationQueryRequest() {
        return Map.of(
                "type", "DCQL",
                "scope", VERIFICATION_QUERY_SCOPE,
                "query", Map.of(
                        "credentials", List.of(Map.of(
                                "id", "employment-verification",
                                "format", "dc+sd-jwt",
                                "meta", Map.of("vct_values", List.of(PROTECTED_VCT)),
                                "claims", List.of(
                                        Map.of("path", List.of("last_name")),
                                        Map.of("path", List.of("first_name"))
                                )
                        ))
                )
        );
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

    private String tamperJwtSignature(String jwt) {
        return jwt + "A";
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
