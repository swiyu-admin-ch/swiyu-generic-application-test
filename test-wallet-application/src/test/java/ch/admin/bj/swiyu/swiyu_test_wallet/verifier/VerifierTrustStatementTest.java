package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.verifier.model.ConfigurationOverrideDto;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationPurpose;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementRouteSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseVerifiers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JwtSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.fasterxml.jackson.annotation.JsonInclude;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementRouteSupport.TP2_PROFILE_VERSION;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseVerifiers({VerifierVariant.DEFAULT, VerifierVariant.CACHED})
class VerifierTrustStatementTest extends BaseTest {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();
    private static final Duration CACHED_TRUST_STATEMENT_LIFETIME = Duration.ofMinutes(4);
    private static final Duration SHORT_TRUST_STATEMENT_LIFETIME = Duration.ofSeconds(3);
    private static final Duration EXPIRY_WAIT_CUSHION = Duration.ofSeconds(6);
    private static final String IDENTITY_TRUST_STATEMENT_TYPE = "swiyu-identity-trust-statement+jwt";
    private static final String PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE =
            "swiyu-protected-verification-authorization-trust-statement+jwt";
    private static final String VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE =
            "swiyu-verification-query-public-statement+jwt";

    @BeforeEach
    void useDefaultVerifier() {
        useVerifier(verifier(VerifierVariant.DEFAULT));
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-981",
            summary = "Request object contains cached verifier idTS and pvaTS",
            description = """
                    Given valid TP2 verifier trust statements.
                    When the wallet fetches the signed OID4VP request object twice.
                    Then verifier_info contains valid idTS and pvaTS entries and the second fetch reuses the cache.
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "The TP 2.0 is not available yet."
    )
    void tenantVerifierRequestObject_whenTp2Enabled_thenVerifierInfoContainsIdTsAndPvaTs() {
        useCachedVerifier();
        final Tp2TrustStatementRouteSupport tp2Routes = tp2Routes();

        // Given
        tp2Routes.registerVerifierSuccess(CACHED_TRUST_STATEMENT_LIFETIME);
        final String verifierDid = swiyuDidVariant(verifierConfig.getVerifierDid());
        final ManagementResponse managementResponse = createVerification(verifierDid);
        final int idTsCallsBefore = tp2Routes.identityTrustStatementRequests(verifierDid);
        final int pvaTsCallsBefore = tp2Routes.protectedVerificationAuthorizationRequests(verifierDid);

        try {
            // When
            final String firstRequestObject = wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            );
            final JsonNode firstVerifierInfo = verifierInfo(firstRequestObject);
            final String firstIdTs = firstVerifierInfoEntry(firstVerifierInfo, IDENTITY_TRUST_STATEMENT_TYPE);
            final String firstPvaTs = firstVerifierInfoEntry(
                    firstVerifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE
            );

            // Then
            assertVerifierInfoEntries(firstVerifierInfo);
            assertVerifierInfoStatementSubject(firstVerifierInfo, IDENTITY_TRUST_STATEMENT_TYPE, verifierDid);
            assertVerifierInfoStatementSubject(
                    firstVerifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE,
                    verifierDid
            );
            assertThat(firstVerifierInfoEntry(firstVerifierInfo, VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE)).isBlank();
            assertThat(tp2Routes.identityTrustStatementRequests(verifierDid)).isEqualTo(idTsCallsBefore + 1);
            assertThat(tp2Routes.protectedVerificationAuthorizationRequests(verifierDid))
                    .isEqualTo(pvaTsCallsBefore + 1);

            // When
            final JsonNode repeatedVerifierInfo = verifierInfo(wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            ));

            // Then
            assertThat(firstVerifierInfoEntry(repeatedVerifierInfo, IDENTITY_TRUST_STATEMENT_TYPE)).isEqualTo(firstIdTs);
            assertThat(firstVerifierInfoEntry(
                    repeatedVerifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE
            )).isEqualTo(firstPvaTs);
            assertThat(tp2Routes.identityTrustStatementRequests(verifierDid)).isEqualTo(idTsCallsBefore + 1);
            assertThat(tp2Routes.protectedVerificationAuthorizationRequests(verifierDid))
                    .isEqualTo(pvaTsCallsBefore + 1);
        } finally {
            tp2Routes.restoreDefaults(issuerConfig, verifierConfig, trustConfig, OBJECT_MAPPER);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1100",
            summary = "Verifier trust-statement cache is scoped by verifier DID",
            description = """
                    Given two verification requests with different verifier DID overrides.
                    When the wallet fetches both signed request objects.
                    Then idTS and pvaTS subjects match the effective verifier DID and are not reused across subjects.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "The TP 2.0 is not available yet."
    )
    void tenantVerifierRequestObject_whenVerifierDidChanges_thenTrustStatementCacheIsSubjectScoped() {
        useCachedVerifier();
        final Tp2TrustStatementRouteSupport tp2Routes = tp2Routes();

        // Given
        tp2Routes.registerVerifierSuccess(CACHED_TRUST_STATEMENT_LIFETIME);
        final String firstVerifierDid = swiyuDidVariant(verifierConfig.getVerifierDid());
        final String secondVerifierDid = swiyuDidVariant(verifierConfig.getVerifierDid());

        try {
            // When
            final JsonNode firstVerifierInfo = verifierInfo(wallet.getVerificationDetailSigned(
                    createVerification(firstVerifierDid).getVerificationDeeplink()
            ));
            final JsonNode secondVerifierInfo = verifierInfo(wallet.getVerificationDetailSigned(
                    createVerification(secondVerifierDid).getVerificationDeeplink()
            ));

            // Then
            assertVerifierInfoStatementSubject(firstVerifierInfo, IDENTITY_TRUST_STATEMENT_TYPE, firstVerifierDid);
            assertVerifierInfoStatementSubject(
                    firstVerifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE,
                    firstVerifierDid
            );
            assertVerifierInfoStatementSubject(secondVerifierInfo, IDENTITY_TRUST_STATEMENT_TYPE, secondVerifierDid);
            assertVerifierInfoStatementSubject(
                    secondVerifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE,
                    secondVerifierDid
            );
            assertThat(firstVerifierInfoEntry(firstVerifierInfo, IDENTITY_TRUST_STATEMENT_TYPE))
                    .isNotEqualTo(firstVerifierInfoEntry(secondVerifierInfo, IDENTITY_TRUST_STATEMENT_TYPE));
            assertThat(firstVerifierInfoEntry(
                    firstVerifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE
            )).isNotEqualTo(firstVerifierInfoEntry(
                    secondVerifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE
            ));
        } finally {
            tp2Routes.restoreDefaults(issuerConfig, verifierConfig, trustConfig, OBJECT_MAPPER);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-983",
            summary = "Verifier refreshes expired idTS and pvaTS",
            description = """
                    Given short-lived verifier idTS and pvaTS values.
                    When the wallet fetches the same request object after statement expiration.
                    Then the verifier refetches and injects fresh trust statements.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "The TP 2.0 is not available yet."
    )
    void tenantVerifierRequestObject_whenTrustStatementExpReached_thenRefetchesFromTms() {
        useCachedVerifier();
        final Tp2TrustStatementRouteSupport tp2Routes = tp2Routes();

        // Given
        tp2Routes.registerVerifierSuccess(SHORT_TRUST_STATEMENT_LIFETIME);
        final String verifierDid = swiyuDidVariant(verifierConfig.getVerifierDid());
        final ManagementResponse managementResponse = createVerification(verifierDid);
        final int idTsCallsBefore = tp2Routes.identityTrustStatementRequests(verifierDid);
        final int pvaTsCallsBefore = tp2Routes.protectedVerificationAuthorizationRequests(verifierDid);

        try {
            // When
            final JsonNode firstVerifierInfo = verifierInfo(wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            ));
            final String firstIdTs = firstVerifierInfoEntry(firstVerifierInfo, IDENTITY_TRUST_STATEMENT_TYPE);
            final String firstPvaTs = firstVerifierInfoEntry(
                    firstVerifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE
            );

            // Then
            assertThat(firstIdTs).isNotBlank();
            assertThat(firstPvaTs).isNotBlank();

            // When
            awaitTrustStatementsExpired(firstIdTs, firstPvaTs);
            final JsonNode refreshedVerifierInfo = verifierInfo(wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            ));

            // Then
            assertThat(firstVerifierInfoEntry(refreshedVerifierInfo, IDENTITY_TRUST_STATEMENT_TYPE))
                    .isNotBlank()
                    .isNotEqualTo(firstIdTs);
            assertThat(firstVerifierInfoEntry(
                    refreshedVerifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE
            )).isNotBlank()
                    .isNotEqualTo(firstPvaTs);
            assertThat(tp2Routes.identityTrustStatementRequests(verifierDid)).isEqualTo(idTsCallsBefore + 2);
            assertThat(tp2Routes.protectedVerificationAuthorizationRequests(verifierDid))
                    .isEqualTo(pvaTsCallsBefore + 2);
        } finally {
            tp2Routes.restoreDefaults(issuerConfig, verifierConfig, trustConfig, OBJECT_MAPPER);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1102",
            summary = "TP2-enriched verifier request object remains usable in a full wallet flow",
            description = """
                    Given a wallet holding a matching credential and a TP2-enriched verifier request object.
                    When the wallet submits a presentation.
                    Then the verifier accepts the presentation and reaches SUCCESS.
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "The TP 2.0 is not available yet."
    )
    void tenantVerifierSubmission_whenTp2TrustInfoPresent_thenVerificationSucceeds() {
        final Tp2TrustStatementRouteSupport tp2Routes = tp2Routes();

        // Given
        tp2Routes.registerVerifierSuccess(CACHED_TRUST_STATEMENT_LIFETIME);
        final var issuedCredential = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                CredentialSubjectFixtures.completeEmployeeProfile()
        );
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(issuedCredential.getOfferDeeplink()));
        final ManagementResponse managementResponse = createVerification();

        try {
            // When
            final String requestObjectJwt = wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            );
            final JsonNode verifierInfo = verifierInfo(requestObjectJwt);

            // Then
            assertVerifierInfoStatementSubject(verifierInfo, IDENTITY_TRUST_STATEMENT_TYPE, configuredVerifierDid());
            assertVerifierInfoStatementSubject(
                    verifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE,
                    configuredVerifierDid()
            );

            // When
            final RequestObject requestObject = parseSignedVerificationRequestObject(requestObjectJwt);
            final String presentation = batchEntry.createPresentationForSdJwtIndex(0, requestObject);
            wallet.respondToVerification(requestObject, presentation);

            // Then
            verifierManager.verifyState(managementResponse.getId(), VerificationStatus.SUCCESS);
        } finally {
            tp2Routes.restoreDefaults(issuerConfig, verifierConfig, trustConfig, OBJECT_MAPPER);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1097",
            summary = "Verifier skips invalid idTS and keeps valid pvaTS",
            description = """
                    Given the registry returns an idTS with an invalid signature and a valid pvaTS.
                    When the wallet fetches the signed request object.
                    Then verifier_info omits idTS and still contains the valid pvaTS.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "The TP 2.0 is not available yet."
    )
    void tenantVerifierRequestObject_whenIdentityTrustStatementSignatureInvalid_thenIdTsIsSkipped() {
        useCachedVerifier();
        final Tp2TrustStatementRouteSupport tp2Routes = tp2Routes();

        // Given
        tp2Routes.registerVerifierInvalidIdentity(CACHED_TRUST_STATEMENT_LIFETIME);
        final String verifierDid = swiyuDidVariant(verifierConfig.getVerifierDid());
        final ManagementResponse managementResponse = createVerification(verifierDid);

        try {
            // When
            final JsonNode verifierInfo = verifierInfo(wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            ));
            final Set<String> types = statementTypes(verifierInfo);

            // Then
            assertThat(types).doesNotContain(IDENTITY_TRUST_STATEMENT_TYPE);
            assertThat(types).contains(PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE);
            assertVerifierInfoStatementSubject(
                    verifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE,
                    verifierDid
            );
        } finally {
            tp2Routes.restoreDefaults(issuerConfig, verifierConfig, trustConfig, OBJECT_MAPPER);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1099",
            summary = "Verifier retries TP2 trust statements after a transient TMS outage",
            description = """
                    Given the registry returns one transient error for idTS and pvaTS before recovering.
                    When the wallet fetches the same signed request object three times in immediate succession.
                    Then the first response omits verifier_info, the second retries and recovers, and the third reuses
                    the validated statements from cache.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "The TP 2.0 is not available yet."
    )
    void tenantVerifierRequestObject_whenTmsTransientOutage_thenRetriesAndCachesRecovery() {
        useCachedVerifier();
        final Tp2TrustStatementRouteSupport tp2Routes = tp2Routes();

        // Given
        tp2Routes.registerVerifierTransientErrorThenSuccess(CACHED_TRUST_STATEMENT_LIFETIME);
        final String verifierDid = swiyuDidVariant(verifierConfig.getVerifierDid());
        final ManagementResponse managementResponse = createVerification(verifierDid);
        final int idTsCallsBefore = tp2Routes.identityTrustStatementRequests(verifierDid);
        final int pvaTsCallsBefore = tp2Routes.protectedVerificationAuthorizationRequests(verifierDid);

        try {
            // When
            final JsonNode firstVerifierInfo = verifierInfo(wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            ));
            assertVerifierInfoAbsent(firstVerifierInfo);
            assertThat(tp2Routes.identityTrustStatementRequests(verifierDid)).isEqualTo(idTsCallsBefore + 1);
            assertThat(tp2Routes.protectedVerificationAuthorizationRequests(verifierDid))
                    .isEqualTo(pvaTsCallsBefore + 1);

            // When
            final JsonNode recoveredVerifierInfo = verifierInfo(wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            ));
            final String recoveredIdTs = firstVerifierInfoEntry(
                    recoveredVerifierInfo,
                    IDENTITY_TRUST_STATEMENT_TYPE
            );
            final String recoveredPvaTs = firstVerifierInfoEntry(
                    recoveredVerifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE
            );

            // Then
            assertThat(tp2Routes.identityTrustStatementRequests(verifierDid)).isEqualTo(idTsCallsBefore + 2);
            assertThat(tp2Routes.protectedVerificationAuthorizationRequests(verifierDid))
                    .isEqualTo(pvaTsCallsBefore + 2);
            assertVerifierInfoEntries(recoveredVerifierInfo);
            assertVerifierInfoStatementSubject(recoveredVerifierInfo, IDENTITY_TRUST_STATEMENT_TYPE, verifierDid);
            assertVerifierInfoStatementSubject(
                    recoveredVerifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE,
                    verifierDid
            );

            // When
            final JsonNode cachedVerifierInfo = verifierInfo(wallet.getVerificationDetailSigned(
                    managementResponse.getVerificationDeeplink()
            ));

            // Then
            assertThat(firstVerifierInfoEntry(cachedVerifierInfo, IDENTITY_TRUST_STATEMENT_TYPE))
                    .isEqualTo(recoveredIdTs);
            assertThat(firstVerifierInfoEntry(
                    cachedVerifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE
            )).isEqualTo(recoveredPvaTs);
            assertThat(tp2Routes.identityTrustStatementRequests(verifierDid)).isEqualTo(idTsCallsBefore + 2);
            assertThat(tp2Routes.protectedVerificationAuthorizationRequests(verifierDid))
                    .isEqualTo(pvaTsCallsBefore + 2);
        } finally {
            tp2Routes.restoreDefaults(issuerConfig, verifierConfig, trustConfig, OBJECT_MAPPER);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1098",
            summary = "Verifier registers and embeds vqPS on the fly",
            description = """
                    Given verification_purpose transparency metadata and a DCQL query.
                    When verification is created.
                    Then the verifier registers a vqPS, substitutes scope, and embeds the matching vqPS in verifier_info.
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    @Disabled("Re-enable once IF-014 vQPS submission authentication is bearer-jwt only and no longer declares OIDC.")
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "The TP 2.0 is not available yet"
    )
    void tenantVerifierManagement_whenVerificationPurposeProvided_thenRegistersAndEmbedsOnTheFlyVqPs() {
        final Tp2TrustStatementRouteSupport tp2Routes = tp2Routes();

        // Given
        tp2Routes.registerVerifierSuccess(CACHED_TRUST_STATEMENT_LIFETIME);
        final String verifierDid = verifierConfig.getVerifierDid();
        final String scope = "ch.swiyu.tp2.university.presentation." + UUID.randomUUID();
        final VerificationPurpose purpose = verificationPurpose(
                scope,
                "University proof",
                "Verification of university credential claims"
        );
        final int submissionsBefore = tp2Routes.verificationQueryPublicStatementSubmissions();

        try {
            // When
            final var verificationRequest = verifierManager
                    .verificationRequest()
                    .withUniversityDCQL()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .verificationPurpose(purpose)
                    .jwtSecure();
            final JsonNode expectedDcqlQuery = OBJECT_MAPPER.rebuild()
                    .changeDefaultPropertyInclusion(
                            inclusion -> inclusion.withValueInclusion(JsonInclude.Include.NON_NULL)
                    )
                    .build()
                    .valueToTree(verificationRequest.getRequest().getDcqlQuery());
            final ManagementResponse managementResponse = verificationRequest.createManagementResponse();
            final JsonNode requestObjectPayload = JwtSupport.decodePayloadToJsonNode(
                    wallet.getVerificationDetailSigned(managementResponse.getVerificationDeeplink())
            );
            final JsonNode verifierInfo = requestObjectPayload.path("verifier_info");
            final String vqPs = firstVerifierInfoEntry(verifierInfo, VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE);
            final JsonNode vqPsPayload = statementPayload(vqPs);

            // Then
            assertVerifierInfoEntries(verifierInfo);
            assertThat(tp2Routes.verificationQueryPublicStatementSubmissions()).isEqualTo(submissionsBefore + 1);
            assertThat(requestObjectPayload.path("scope").asText()).isEqualTo(scope);
            assertThat(requestObjectPayload.has("dcql_query")).isFalse();
            assertVerifierInfoStatementSubject(verifierInfo, IDENTITY_TRUST_STATEMENT_TYPE, verifierDid);
            assertVerifierInfoStatementSubject(
                    verifierInfo,
                    PROTECTED_VERIFICATION_AUTHORIZATION_TRUST_STATEMENT_TYPE,
                    verifierDid
            );
            assertThat(vqPs).as("verifier_info must contain vqPS").isNotBlank();
            assertVerificationQueryPublicStatement(
                    vqPsPayload,
                    verifierDid,
                    scope,
                    "University proof",
                    "Verification of university credential claims",
                    expectedDcqlQuery
            );
        } finally {
            tp2Routes.restoreDefaults(issuerConfig, verifierConfig, trustConfig, OBJECT_MAPPER);
        }
    }

    private Tp2TrustStatementRouteSupport tp2Routes() {
        return new Tp2TrustStatementRouteSupport(
                mockServerClient,
                issuerConfig,
                verifierConfig,
                trustConfig,
                OBJECT_MAPPER
        );
    }

    private void useCachedVerifier() {
        useVerifier(verifier(VerifierVariant.CACHED));
    }

    private ManagementResponse createVerification() {
        return verifierManager
                .verificationRequest()
                .withUniversityDCQL()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .jwtSecure()
                .createManagementResponse();
    }

    private ManagementResponse createVerification(String verifierDid) {
        return verifierManager
                .verificationRequest()
                .withUniversityDCQL()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .configurationOverride(new ConfigurationOverrideDto().verifierDid(verifierDid))
                .jwtSecure()
                .createManagementResponse();
    }

    private String configuredVerifierDid() {
        return verifierConfig.getVerifierDid();
    }

    private VerificationPurpose verificationPurpose(String scope, String purposeName, String purposeDescription) {
        return new VerificationPurpose()
                .scope(scope)
                .purposeName(Map.of("en", purposeName))
                .purposeDescription(Map.of("en", purposeDescription));
    }

    private JsonNode verifierInfo(String requestObjectJwt) {
        return JwtSupport.decodePayloadToJsonNode(requestObjectJwt).path("verifier_info");
    }

    private RequestObject parseSignedVerificationRequestObject(final String signedRequestObjectJwt) {
        try {
            return OBJECT_MAPPER.readValue(
                    JwtSupport.decodePayload(signedRequestObjectJwt),
                    RequestObject.class
            );
        } catch (JacksonException e) {
            throw new IllegalStateException("Failed to parse signed verification request object", e);
        }
    }

    private void assertVerifierInfoEntries(JsonNode verifierInfo) {
        assertThat(verifierInfo.isArray()).as("verifier_info must be an array").isTrue();
        for (JsonNode entry : verifierInfo) {
            assertThat(entry.path("format").asText()).isEqualTo("jwt");
            assertThat(entry.path("credential_ids").isMissingNode()).isTrue();
            final String statement = entry.path("data").asText();
            assertThat(statement).isNotBlank();
            assertThat(statement.split("\\.").length).isEqualTo(3);
            assertThat(JWSAlgorithm.ES256.equals(JwtSupport.parse(statement).getHeader().getAlgorithm())).isTrue();
            assertThat(statementProfileVersion(statement)).isEqualTo(TP2_PROFILE_VERSION);
            final String jti = statementPayload(statement).path("jti").asText();
            assertThat(jti).isNotBlank();
            assertThat(UUID.fromString(jti).version()).isEqualTo(4);
        }
    }

    private void assertVerifierInfoStatementSubject(
            JsonNode verifierInfo,
            String expectedType,
            String expectedSubject) {
        final String statement = firstVerifierInfoEntry(verifierInfo, expectedType);
        assertThat(statement).as("verifier_info must contain " + expectedType).isNotBlank();
        assertThat(statementPayload(statement).path("sub").asText()).isEqualTo(expectedSubject);
    }

    private void assertVerificationQueryPublicStatement(JsonNode payload,
                                                        String expectedSubject,
                                                        String expectedScope,
                                                        String expectedPurposeName,
                                                        String expectedPurposeDescription,
                                                        JsonNode expectedDcqlQuery) {
        assertThat(payload.path("sub").asText()).isEqualTo(expectedSubject);
        assertThat(payload.path("purpose_name").asText()).isEqualTo(expectedPurposeName);
        assertThat(payload.path("purpose_name").asText().length()).isLessThanOrEqualTo(40);
        assertThat(payload.path("purpose_name#en").asText()).isEqualTo(expectedPurposeName);
        assertThat(payload.path("purpose_description").asText()).isEqualTo(expectedPurposeDescription);
        assertThat(payload.path("purpose_description").asText().length()).isLessThanOrEqualTo(1000);
        assertThat(payload.path("purpose_description#en").asText()).isEqualTo(expectedPurposeDescription);

        final JsonNode request = payload.path("request");
        assertThat(request.path("type").asText()).isEqualTo("DCQL");
        assertThat(request.path("scope").asText()).isEqualTo(expectedScope);
        assertThat(request.path("query")).isEqualTo(expectedDcqlQuery);
        assertDcqlQueryContainsVctValues(request.path("query"));
    }

    private void assertDcqlQueryContainsVctValues(JsonNode query) {
        final JsonNode credentials = query.path("credentials");
        assertThat(credentials.isArray()).as("DCQL query credentials must be an array").isTrue();
        assertThat(credentials.size()).as("DCQL query credentials must be non-empty").isPositive();
        for (JsonNode credential : credentials) {
            final JsonNode vctValues = credential.path("meta").path("vct_values");
            assertThat(vctValues.isArray()).as("Each DCQL credential query must contain meta.vct_values").isTrue();
            assertThat(vctValues.size()).as("meta.vct_values must be non-empty").isPositive();
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

    private String firstVerifierInfoEntry(JsonNode verifierInfo, String expectedType) {
        return StreamSupport.stream(verifierInfo.spliterator(), false)
                .filter(node -> expectedType.equals(statementType(node.path("data").asText())))
                .map(node -> node.path("data").asText())
                .findFirst()
                .orElse("");
    }

    private String statementType(String statementJwt) {
        if (statementJwt == null || statementJwt.isBlank()) {
            return "";
        }
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

    private void awaitTrustStatementsExpired(String idTs, String pvaTs) {
        final Instant earliestExpiry = earliestExpiry(idTs, pvaTs);
        await()
                .pollInterval(Duration.ofMillis(100))
                .atMost(SHORT_TRUST_STATEMENT_LIFETIME.plus(EXPIRY_WAIT_CUSHION))
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
}
