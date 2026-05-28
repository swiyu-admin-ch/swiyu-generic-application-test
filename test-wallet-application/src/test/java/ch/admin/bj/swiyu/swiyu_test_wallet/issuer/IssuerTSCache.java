package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.ConfigurationOverride;
import ch.admin.bj.swiyu.gen.issuer.model.CreateCredentialOfferRequest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialOfferMetadataDto;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.IssuerMetadata;
import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.gen.issuer.model.StatusListCreate;
import ch.admin.bj.swiyu.gen.issuer.model.StatusListCreateConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustRegistryMockServerConfigurer;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.support.TestConstants;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
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

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.awaitility.Awaitility.await;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
public class IssuerTSCache extends BaseTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().findAndRegisterModules();
    private static final Duration CACHED_TRUST_STATEMENT_LIFETIME = Duration.ofMinutes(5);
    private static final Duration SHORT_TRUST_STATEMENT_LIFETIME = Duration.ofSeconds(5);
    private static final String IDENTITY_TRUST_STATEMENT_PATH = "/api/v2/identity-trust-statement";
    private static final String PROTECTED_ISSUANCE_AUTHORIZATION_PATH =
            "/api/v2/protected-issuance-authorization-trust-statement";
    private static final String PROTECTED_CREDENTIAL_CONFIGURATION_ID =
            CredentialConfigurationFixtures.UNIVERSITY_EXAMPLE_HIGH_KEY_ATTESTATION_REQUIRED_SD_JWT;
    private static final String PROTECTED_ISSUANCE_AUTHORIZATION_TRUST_STATEMENT =
            "protected_issuance_authorization_trust_statement";
    private static final String TP2_PROFILE_VERSION = "swiss-profile-trust:1.0.0";
    private static final String IDENTITY_TRUST_STATEMENT_TYPE = "swiyu-identity-trust-statement+jwt";
    private static final String PROTECTED_ISSUANCE_AUTHORIZATION_TRUST_STATEMENT_TYPE =
            "swiyu-protected-issuance-authorization-trust-statement+jwt";
    private static final String TP2_STATUS_LIST_URI =
            "https://mockserver:1080/api/v1/statuslist/tp2-trust-statements.jwt";
    private static final String PROTECTED_VCT = TestConstants.ISSUER_URL + "/oid4vci/vct/my-vct-v01";

    @Test
    @XrayTest(
            key = "EIDOMNI-965",
            summary = "Issuer metadata includes cached idTS and piaTS",
            description = """
                    This test validates that the Wallet OID4VCI metadata request receives cached TP2 trust statements.
                    It checks the issuer idTS at the metadata root and the matching piaTS on the protected credential
                    configuration.
                    It expects the second metadata request to reuse cached statements without another Trust Registry
                    fetch.
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void tenantIssuerMetadata_whenTrustStatementsCached_thenInjectsStatementsAndReusesCache() {
        // Given
        final ConfigurationOverride configurationOverride = uniqueConfigurationOverride();
        final CredentialWithDeeplinkResponse offer = createCredentialOffer(configurationOverride);
        final WalletBatchEntry walletEntry = wallet.createWalletBatchEntry();
        walletEntry.receiveDeepLinkAndValidateIt(toUri(offer.getOfferDeeplink()));

        replaceIssuerTrustStatementRoutesWithSuccessfulResponses(CACHED_TRUST_STATEMENT_LIFETIME);
        try {
            final int idTsCallsBefore = countIdentityTrustStatementRequests();
            final int piaTsCallsBefore = countProtectedIssuanceAuthorizationRequests();

            // When
            final IssuerMetadata firstMetadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final JsonNode firstRawMetadata = walletEntry.getIssuerMetadataRaw();
            final String firstIdTs = firstMetadata.getCredentialIssuerIdentityTrustStatement();
            final String firstPiaTs = protectedIssuanceAuthorizationTrustStatement(firstRawMetadata);

            // Then
            assertThat(firstIdTs)
                    .as("Metadata must include the credential issuer identity trust statement")
                    .isNotBlank();
            assertThat(firstPiaTs)
                    .as("Protected credential configuration must include the matching piaTS")
                    .isNotBlank();
            assertIdentityTrustStatement(firstIdTs, configurationOverride.getIssuerDid());
            assertProtectedIssuanceAuthorizationTrustStatement(firstPiaTs, configurationOverride.getIssuerDid());
            assertThat(countIdentityTrustStatementRequests()).isEqualTo(idTsCallsBefore + 1);
            assertThat(countProtectedIssuanceAuthorizationRequests()).isEqualTo(piaTsCallsBefore + 1);

            // When
            final IssuerMetadata repeatedMetadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final JsonNode repeatedRawMetadata = walletEntry.getIssuerMetadataRaw();

            // Then
            assertThat(repeatedMetadata.getCredentialIssuerIdentityTrustStatement())
                    .as("Repeated metadata response must reuse the cached idTS")
                    .isEqualTo(firstIdTs);
            assertThat(protectedIssuanceAuthorizationTrustStatement(repeatedRawMetadata))
                    .as("Repeated metadata response must reuse the cached piaTS")
                    .isEqualTo(firstPiaTs);
            assertThat(countIdentityTrustStatementRequests()).isEqualTo(idTsCallsBefore + 1);
            assertThat(countProtectedIssuanceAuthorizationRequests()).isEqualTo(piaTsCallsBefore + 1);
        } finally {
            restoreDefaultIssuerTrustStatementRoutes();
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-972",
            summary = "Issuer metadata refetches trust statements after exp-based cache eviction",
            description = """
                    This test validates that issuer metadata evicts TP2 trust statements after their JWT exp time.
                    It first fetches metadata with short-lived idTS and piaTS values and records the Trust Registry
                    request counts.
                    It expects a later metadata request after expiry to return fresh statements and call the Trust
                    Registry again.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void tenantIssuerMetadata_whenTrustStatementExpReached_thenRefetchesTrustStatements() {
        // Given
        final ConfigurationOverride configurationOverride = uniqueConfigurationOverride();
        final CredentialWithDeeplinkResponse offer = createCredentialOffer(configurationOverride);
        final WalletBatchEntry walletEntry = wallet.createWalletBatchEntry();
        walletEntry.receiveDeepLinkAndValidateIt(toUri(offer.getOfferDeeplink()));

        replaceIssuerTrustStatementRoutesWithSuccessfulResponses(SHORT_TRUST_STATEMENT_LIFETIME);
        try {
            final int idTsCallsBefore = countIdentityTrustStatementRequests();
            final int piaTsCallsBefore = countProtectedIssuanceAuthorizationRequests();

            // When
            final IssuerMetadata firstMetadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final JsonNode firstRawMetadata = walletEntry.getIssuerMetadataRaw();
            final String firstIdTs = firstMetadata.getCredentialIssuerIdentityTrustStatement();
            final String firstPiaTs = protectedIssuanceAuthorizationTrustStatement(firstRawMetadata);

            // Then
            assertThat(firstIdTs)
                    .as("First metadata response must include idTS")
                    .isNotBlank();
            assertThat(firstPiaTs)
                    .as("First metadata response must include piaTS for the protected credential configuration")
                    .isNotBlank();
            assertIdentityTrustStatement(firstIdTs, configurationOverride.getIssuerDid());
            assertProtectedIssuanceAuthorizationTrustStatement(firstPiaTs, configurationOverride.getIssuerDid());
            assertThat(countIdentityTrustStatementRequests()).isEqualTo(idTsCallsBefore + 1);
            assertThat(countProtectedIssuanceAuthorizationRequests()).isEqualTo(piaTsCallsBefore + 1);

            // When
            awaitTrustStatementsExpired(firstIdTs, firstPiaTs);
            final IssuerMetadata refreshedMetadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final JsonNode refreshedRawMetadata = walletEntry.getIssuerMetadataRaw();

            // Then
            assertThat(refreshedMetadata.getCredentialIssuerIdentityTrustStatement())
                    .as("Metadata response after idTS expiry must include a freshly fetched idTS")
                    .isNotBlank()
                    .isNotEqualTo(firstIdTs);
            assertThat(protectedIssuanceAuthorizationTrustStatement(refreshedRawMetadata))
                    .as("Metadata response after piaTS expiry must include a freshly fetched piaTS")
                    .isNotBlank()
                    .isNotEqualTo(firstPiaTs);
            assertIdentityTrustStatement(
                    refreshedMetadata.getCredentialIssuerIdentityTrustStatement(),
                    configurationOverride.getIssuerDid()
            );
            assertProtectedIssuanceAuthorizationTrustStatement(
                    protectedIssuanceAuthorizationTrustStatement(refreshedRawMetadata),
                    configurationOverride.getIssuerDid()
            );
            assertThat(countIdentityTrustStatementRequests()).isEqualTo(idTsCallsBefore + 2);
            assertThat(countProtectedIssuanceAuthorizationRequests()).isEqualTo(piaTsCallsBefore + 2);
        } finally {
            restoreDefaultIssuerTrustStatementRoutes();
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-973",
            summary = "Issuer metadata retries TMS immediately after trust statement fetch error",
            description = """
                    This test validates that a failed TP2 trust statement fetch is not cached as a final metadata value.
                    It makes the Trust Registry return an error for the first metadata request and valid statements for
                    the next request.
                    It expects the next metadata request to retry immediately and inject the valid statements.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void tenantIssuerMetadata_whenTrustStatementFetchFails_thenNextRequestRetriesImmediately() {
        // Given
        final ConfigurationOverride configurationOverride = uniqueConfigurationOverride();
        final CredentialWithDeeplinkResponse offer = createCredentialOffer(configurationOverride);
        final WalletBatchEntry walletEntry = wallet.createWalletBatchEntry();
        walletEntry.receiveDeepLinkAndValidateIt(toUri(offer.getOfferDeeplink()));

        replaceIssuerTrustStatementRoutesWithFirstErrorThenSuccessResponses();
        try {
            final int idTsCallsBefore = countIdentityTrustStatementRequests();
            final int piaTsCallsBefore = countProtectedIssuanceAuthorizationRequests();

            // When
            wallet.getIssuerWellKnownMetadata(walletEntry);

            // Then
            assertThat(countIdentityTrustStatementRequests())
                    .as("First metadata request must attempt the idTS fetch")
                    .isEqualTo(idTsCallsBefore + 1);
            assertThat(countProtectedIssuanceAuthorizationRequests())
                    .as("First metadata request must attempt the piaTS fetch")
                    .isEqualTo(piaTsCallsBefore + 1);

            // When
            final IssuerMetadata retriedMetadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final JsonNode retriedRawMetadata = walletEntry.getIssuerMetadataRaw();
            final String retriedIdTs = retriedMetadata.getCredentialIssuerIdentityTrustStatement();
            final String retriedPiaTs = protectedIssuanceAuthorizationTrustStatement(retriedRawMetadata);

            // Then
            assertThat(countIdentityTrustStatementRequests())
                    .as("Metadata request after TMS error must retry the idTS fetch immediately")
                    .isEqualTo(idTsCallsBefore + 2);
            assertThat(countProtectedIssuanceAuthorizationRequests())
                    .as("Metadata request after TMS error must retry the piaTS fetch immediately")
                    .isEqualTo(piaTsCallsBefore + 2);
            assertThat(retriedIdTs)
                    .as("Metadata request after TMS error must retry and inject idTS")
                    .isNotBlank();
            assertThat(retriedPiaTs)
                    .as("Metadata request after TMS error must retry and inject piaTS")
                    .isNotBlank();
            assertIdentityTrustStatement(retriedIdTs, configurationOverride.getIssuerDid());
            assertProtectedIssuanceAuthorizationTrustStatement(retriedPiaTs, configurationOverride.getIssuerDid());
        } finally {
            restoreDefaultIssuerTrustStatementRoutes();
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-995",
            summary = "Issuer metadata does not invalidate idTS cache when piaTS VCT does not match",
            description = """
                    This test validates that issuer metadata skips TP2 piaTS injection when the Trust Registry returns
                    no statement matching the protected credential configuration VCT.
                    It expects the cached idTS and piaTS list to remain cached so the next metadata request does not
                    call the Trust Registry again.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void tenantIssuerMetadata_whenPiaTsVctDoesNotMatch_thenDoesNotInvalidateTrustStatementCache() {
        // Given
        final ConfigurationOverride configurationOverride = uniqueConfigurationOverride();
        final CredentialWithDeeplinkResponse offer = createCredentialOffer(configurationOverride);
        final WalletBatchEntry walletEntry = wallet.createWalletBatchEntry();
        walletEntry.receiveDeepLinkAndValidateIt(toUri(offer.getOfferDeeplink()));

        replaceIssuerTrustStatementRoutesWithMismatchedPiaTsResponses(CACHED_TRUST_STATEMENT_LIFETIME);
        try {
            final int idTsCallsBefore = countIdentityTrustStatementRequests();
            final int piaTsCallsBefore = countProtectedIssuanceAuthorizationRequests();

            // When
            final IssuerMetadata firstMetadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final JsonNode firstRawMetadata = walletEntry.getIssuerMetadataRaw();
            final String firstIdTs = firstMetadata.getCredentialIssuerIdentityTrustStatement();

            // Then
            assertThat(firstIdTs)
                    .as("Metadata must still include idTS when no piaTS VCT matches")
                    .isNotBlank();
            assertThat(protectedIssuanceAuthorizationTrustStatement(firstRawMetadata))
                    .as("Metadata must not inject a piaTS for a non-matching VCT")
                    .isNull();
            assertIdentityTrustStatement(firstIdTs, configurationOverride.getIssuerDid());
            assertThat(countIdentityTrustStatementRequests()).isEqualTo(idTsCallsBefore + 1);
            assertThat(countProtectedIssuanceAuthorizationRequests()).isEqualTo(piaTsCallsBefore + 1);

            // When
            final IssuerMetadata repeatedMetadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final JsonNode repeatedRawMetadata = walletEntry.getIssuerMetadataRaw();

            // Then
            assertThat(repeatedMetadata.getCredentialIssuerIdentityTrustStatement())
                    .as("No matching piaTS must not invalidate the cached idTS")
                    .isNotBlank();
            assertThat(protectedIssuanceAuthorizationTrustStatement(repeatedRawMetadata))
                    .as("Repeated metadata must still omit a non-matching piaTS")
                    .isNull();
            assertThat(countIdentityTrustStatementRequests())
                    .as("No matching piaTS must not trigger another idTS fetch")
                    .isEqualTo(idTsCallsBefore + 1);
            assertThat(countProtectedIssuanceAuthorizationRequests())
                    .as("No matching piaTS must not trigger another piaTS list fetch")
                    .isEqualTo(piaTsCallsBefore + 1);
        } finally {
            restoreDefaultIssuerTrustStatementRoutes();
        }
    }

    private ConfigurationOverride uniqueConfigurationOverride() {
        final String issuerDid = issuerConfig.getIssuerDid() + ":cachetest" + UUID.randomUUID()
                .toString()
                .replace("-", "");

        return new ConfigurationOverride()
                .issuerDid(issuerDid)
                .verificationMethod(issuerDid + "#assert-key-01");
    }

    private CredentialWithDeeplinkResponse createCredentialOffer(ConfigurationOverride configurationOverride) {
        final StatusList statusList = createStatusList(configurationOverride);
        final CreateCredentialOfferRequest offerRequest = new CreateCredentialOfferRequest()
                .metadataCredentialSupportedId(List.of(PROTECTED_CREDENTIAL_CONFIGURATION_ID))
                .credentialSubjectData(CredentialSubjectFixtures.completeEmployeeProfile())
                .credentialMetadata(new CredentialOfferMetadataDto().deferred(false))
                .offerValiditySeconds(86400)
                .statusLists(List.of(statusList.getStatusRegistryUrl()))
                .configurationOverride(configurationOverride);

        return issuerManager.createCredential(offerRequest);
    }

    private StatusList createStatusList(ConfigurationOverride configurationOverride) {
        final StatusListCreate statusListCreate = new StatusListCreate()
                .maxLength(100000)
                .config(new StatusListCreateConfig().bits(2))
                .configurationOverride(configurationOverride);

        return issuerManager.getStatusListApi().createStatusList(statusListCreate);
    }

    private void replaceIssuerTrustStatementRoutesWithSuccessfulResponses(Duration lifetime) {
        replaceIssuerTrustStatementRoutesWithSuccessfulResponses(lifetime, PROTECTED_VCT);
    }

    private void replaceIssuerTrustStatementRoutesWithMismatchedPiaTsResponses(Duration lifetime) {
        replaceIssuerTrustStatementRoutesWithSuccessfulResponses(lifetime, PROTECTED_VCT + "/mismatch");
    }

    private void replaceIssuerTrustStatementRoutesWithSuccessfulResponses(Duration lifetime, String piaTsVct) {
        clearIssuerTrustStatementRoutes();

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
                        .withBody(buildIdentityTrustStatement(extractLastPathSegment(httpRequest), lifetime)));

        mockServerClient.when(
                        request()
                                .withMethod("GET")
                                .withPath(PROTECTED_ISSUANCE_AUTHORIZATION_PATH + "/?"),
                        Times.unlimited(),
                        TimeToLive.unlimited(),
                        100
                )
                .respond(httpRequest -> response()
                        .withStatusCode(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(protectedIssuanceAuthorizationResponse(
                                httpRequest.getFirstQueryStringParameter("sub"),
                                lifetime,
                                piaTsVct
                        )));
    }

    private void replaceIssuerTrustStatementRoutesWithFirstErrorThenSuccessResponses() {
        clearIssuerTrustStatementRoutes();

        final AtomicInteger idTsAttempts = new AtomicInteger();
        final AtomicInteger piaTsAttempts = new AtomicInteger();

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
                                    CACHED_TRUST_STATEMENT_LIFETIME
                            ));
                });

        mockServerClient.when(
                        request()
                                .withMethod("GET")
                                .withPath(PROTECTED_ISSUANCE_AUTHORIZATION_PATH + "/?"),
                        Times.unlimited(),
                        TimeToLive.unlimited(),
                        100
                )
                .respond(httpRequest -> {
                    if (piaTsAttempts.getAndIncrement() == 0) {
                        return response()
                                .withStatusCode(503)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"error\":\"temporary piaTS fetch failure\"}");
                    }

                    return response()
                            .withStatusCode(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody(protectedIssuanceAuthorizationResponse(
                                    httpRequest.getFirstQueryStringParameter("sub"),
                                    CACHED_TRUST_STATEMENT_LIFETIME
                            ));
                });
    }

    private void restoreDefaultIssuerTrustStatementRoutes() {
        clearIssuerTrustStatementRoutes();
        Tp2TrustRegistryMockServerConfigurer.registerIssuerTrustStatementRoutes(
                mockServerClient,
                issuerConfig,
                trustConfig,
                OBJECT_MAPPER
        );
    }

    private void clearIssuerTrustStatementRoutes() {
        mockServerClient.clear(
                request().withMethod("GET").withPath(IDENTITY_TRUST_STATEMENT_PATH + "/.+"),
                ClearType.EXPECTATIONS
        );
        mockServerClient.clear(
                request().withMethod("GET").withPath(PROTECTED_ISSUANCE_AUTHORIZATION_PATH + "/?"),
                ClearType.EXPECTATIONS
        );
    }

    private String buildIdentityTrustStatement(String subject, Duration lifetime) {
        return signTrustStatement(
                IDENTITY_TRUST_STATEMENT_TYPE,
                claimsBuilder(subject, lifetime)
                        .claim("status", statusListClaim(0))
                        .claim("entity_name", "Mock TP2 Issuer")
                        .claim("is_state_actor", true)
                        .claim("registry_ids", List.of(Map.of("type", "UID", "value", "CHE-123.456.789")))
                        .build()
        );
    }

    private String buildProtectedIssuanceAuthorizationTrustStatement(String subject, Duration lifetime) {
        return buildProtectedIssuanceAuthorizationTrustStatement(subject, lifetime, PROTECTED_VCT);
    }

    private String buildProtectedIssuanceAuthorizationTrustStatement(String subject, Duration lifetime, String vct) {
        return signTrustStatement(
                PROTECTED_ISSUANCE_AUTHORIZATION_TRUST_STATEMENT_TYPE,
                claimsBuilder(subject, lifetime)
                        .jwtID(UUID.randomUUID().toString())
                        .claim("status", statusListClaim(0))
                        .claim("can_issue", Map.of(
                                "vct", vct,
                                "vct_name", "Protected example issuance",
                                "description", "Protected example issuance."
                        ))
                        .build()
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

    private String protectedIssuanceAuthorizationResponse(String subject, Duration lifetime) {
        return protectedIssuanceAuthorizationResponse(subject, lifetime, PROTECTED_VCT);
    }

    private String protectedIssuanceAuthorizationResponse(String subject, Duration lifetime, String vct) {
        try {
            final List<String> content = List.of(buildProtectedIssuanceAuthorizationTrustStatement(
                    subject,
                    lifetime,
                    vct
            ));
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
            throw new IllegalStateException("Cannot serialize mock piaTS response", e);
        }
    }

    private String protectedIssuanceAuthorizationTrustStatement(JsonNode metadata) {
        final JsonNode node = metadata.path("credential_configurations_supported")
                .path(PROTECTED_CREDENTIAL_CONFIGURATION_ID)
                .path(PROTECTED_ISSUANCE_AUTHORIZATION_TRUST_STATEMENT);

        return node.isMissingNode() || node.isNull() ? null : node.asText();
    }

    private void assertIdentityTrustStatement(String jwt, String expectedSubject) {
        try {
            final SignedJWT statement = SignedJWT.parse(jwt);
            final JWTClaimsSet claimsSet = statement.getJWTClaimsSet();

            assertTrustStatementHeader(statement, IDENTITY_TRUST_STATEMENT_TYPE);
            assertThat(claimsSet.getIssuer()).isEqualTo(trustConfig.getTrustDid());
            assertThat(claimsSet.getSubject()).isEqualTo(expectedSubject);
            assertThat(claimsSet.getIssueTime()).isNotNull();
            assertThat(claimsSet.getNotBeforeTime()).isNotNull();
            assertThat(claimsSet.getExpirationTime()).isNotNull();
            assertThat(claimsSet.getJSONObjectClaim("status")).containsKey("status_list");
            assertThat(claimsSet.getStringClaim("entity_name")).isEqualTo("Mock TP2 Issuer");
            assertThat(claimsSet.getBooleanClaim("is_state_actor")).isTrue();
            assertThat(claimsSet.getClaim("registry_ids"))
                    .isEqualTo(List.of(Map.of("type", "UID", "value", "CHE-123.456.789")));
        } catch (ParseException e) {
            throw new IllegalStateException("Cannot parse idTS from issuer metadata", e);
        }
    }

    private void assertProtectedIssuanceAuthorizationTrustStatement(String jwt, String expectedSubject) {
        try {
            final SignedJWT statement = SignedJWT.parse(jwt);
            final JWTClaimsSet claimsSet = statement.getJWTClaimsSet();

            assertTrustStatementHeader(statement, PROTECTED_ISSUANCE_AUTHORIZATION_TRUST_STATEMENT_TYPE);
            assertThat(claimsSet.getIssuer()).isEqualTo(trustConfig.getTrustDid());
            assertThat(claimsSet.getSubject()).isEqualTo(expectedSubject);
            assertThat(claimsSet.getJWTID()).isNotBlank();
            assertThat(claimsSet.getIssueTime()).isNotNull();
            assertThat(claimsSet.getNotBeforeTime()).isNotNull();
            assertThat(claimsSet.getExpirationTime()).isNotNull();
            assertThat(claimsSet.getJSONObjectClaim("status")).containsKey("status_list");

            @SuppressWarnings("unchecked")
            final Map<String, Object> canIssue = (Map<String, Object>) claimsSet.getClaim("can_issue");
            assertThat(canIssue)
                    .containsEntry("vct", PROTECTED_VCT)
                    .containsEntry("vct_name", "Protected example issuance")
                    .containsEntry("description", "Protected example issuance.");
        } catch (ParseException e) {
            throw new IllegalStateException("Cannot parse piaTS from issuer metadata", e);
        }
    }

    private void assertTrustStatementHeader(SignedJWT statement, String expectedType) {
        assertThat(statement.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
        assertThat(statement.getHeader().getKeyID()).isEqualTo(trustConfig.getTrustAssertKeyId());
        assertThat(statement.getHeader().getType().toString()).isEqualTo(expectedType);
        assertThat(statement.getHeader().getCustomParam("profile_version")).isEqualTo(TP2_PROFILE_VERSION);
    }

    private void awaitTrustStatementsExpired(String idTs, String piaTs) {
        final Instant earliestExpiry = earliestExpiry(idTs, piaTs);
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

    private int countIdentityTrustStatementRequests() {
        return mockServerClient.retrieveRecordedRequests(
                request().withMethod("GET").withPath(IDENTITY_TRUST_STATEMENT_PATH + "/.+")
        ).length;
    }

    private int countProtectedIssuanceAuthorizationRequests() {
        return mockServerClient.retrieveRecordedRequests(
                request().withMethod("GET").withPath(PROTECTED_ISSUANCE_AUTHORIZATION_PATH + "/?")
        ).length;
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
