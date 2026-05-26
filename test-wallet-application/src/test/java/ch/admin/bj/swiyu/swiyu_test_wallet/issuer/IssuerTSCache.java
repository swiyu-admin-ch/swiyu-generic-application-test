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
import java.util.Map;
import java.util.List;
import java.util.UUID;

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
    private static final Duration SHORT_TRUST_STATEMENT_LIFETIME = Duration.ofSeconds(5);
    private static final String IDENTITY_TRUST_STATEMENT_PATH = "/api/v2/identity-trust-statement";
    private static final String PROTECTED_ISSUANCE_AUTHORIZATION_PATH =
            "/api/v2/protected-issuance-authorization-trust-statement";
    private static final String PROTECTED_CREDENTIAL_CONFIGURATION_ID =
            CredentialConfigurationFixtures.UNIVERSITY_EXAMPLE_HIGH_KEY_ATTESTATION_REQUIRED_SD_JWT;
    private static final String PROTECTED_ISSUANCE_AUTHORIZATION_TRUST_STATEMENT =
            "protected_issuance_authorization_trust_statement";
    private static final String TP2_PROFILE_VERSION = "swiss-profile-trust:1.0.0";
    private static final String PROTECTED_VCT = TestConstants.ISSUER_URL + "/oid4vci/vct/my-vct-v01";

    @Test
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Issuer metadata includes cached identity trust statement",
            description = """
                    This test validates that the Wallet OID4VCI collection flow receives issuer metadata
                    containing the cached credential issuer identity trust statement.
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void unboundNonDeferredCredential_whenIssuedAndVerifiedWithDcql_thenSuccess() {
        // Given
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId,
                subjectClaims);
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        // Then
        assertThat(batchEntry.getIssuerMetadata().getCredentialIssuerIdentityTrustStatement())
                .as("Wallet must receive credential_issuer_identity_trust_statement in issuer metadata")
                .isNotBlank().isNotNull().isNotEmpty();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Issuer metadata refetches trust statements after exp-based cache eviction",
            description = """
                    This test validates that the tenant-specific issuer metadata endpoint evicts cached idTS and piaTS
                    entries when their JWT exp claim is reached and performs a fresh TMS fetch on the next metadata
                    request.
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void tenantIssuerMetadata_whenTrustStatementExpReached_thenRefetchesTrustStatements() {
        // Given
        final String issuerDid = issuerConfig.getIssuerDid() + ":cachetest" + UUID.randomUUID()
                .toString()
                .replace("-", "");
        final ConfigurationOverride configurationOverride = new ConfigurationOverride()
                .issuerDid(issuerDid)
                .verificationMethod(issuerDid + "#assert-key-01");
        final CredentialWithDeeplinkResponse offer = createCredentialOffer(configurationOverride);
        final WalletBatchEntry walletEntry = wallet.createWalletBatchEntry();
        walletEntry.receiveDeepLinkAndValidateIt(toUri(offer.getOfferDeeplink()));

        replaceIssuerTrustStatementRoutesWithShortLivedResponses();
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
            assertThat(countIdentityTrustStatementRequests()).isEqualTo(idTsCallsBefore + 2);
            assertThat(countProtectedIssuanceAuthorizationRequests()).isEqualTo(piaTsCallsBefore + 2);
        } finally {
            restoreDefaultIssuerTrustStatementRoutes();
        }
    }

    private CredentialWithDeeplinkResponse createCredentialOffer(ConfigurationOverride configurationOverride) {
        final StatusList statusList = createStatusList(configurationOverride);
        final CreateCredentialOfferRequest offerRequest = new CreateCredentialOfferRequest()
                .metadataCredentialSupportedId(List.of(CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT))
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

    private void replaceIssuerTrustStatementRoutesWithShortLivedResponses() {
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
                        .withBody(buildIdentityTrustStatement(extractLastPathSegment(httpRequest))));

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
                                httpRequest.getFirstQueryStringParameter("sub")
                        )));
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

    private String buildIdentityTrustStatement(String subject) {
        return signTrustStatement(
                "id-ts+jwt",
                claimsBuilder(subject)
                        .claim("entity_name", List.of(Map.of("name", "Mock TP2 Issuer")))
                        .claim("is_state_actor", true)
                        .claim("registry_ids", List.of(Map.of("type", "UID", "value", "CHE-123.456.789")))
                        .build()
        );
    }

    private String buildProtectedIssuanceAuthorizationTrustStatement(String subject) {
        return signTrustStatement(
                "pia-ts+jwt",
                claimsBuilder(subject)
                        .jwtID(UUID.randomUUID().toString())
                        .claim("status", Map.of(
                                "idx", 0,
                                "uri", "https://mockserver:1080/api/v1/statuslist/tp2-trust-statements.jwt"
                        ))
                        .claim("can_issue", Map.of(
                                "vct", PROTECTED_VCT,
                                "vct_name", "Protected example issuance",
                                "description", "Protected example issuance."
                        ))
                        .build()
        );
    }

    private JWTClaimsSet.Builder claimsBuilder(String subject) {
        final Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(trustConfig.getTrustDid())
                .subject(subject)
                .issueTime(java.util.Date.from(now))
                .expirationTime(java.util.Date.from(now.plus(SHORT_TRUST_STATEMENT_LIFETIME)));
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

    private String protectedIssuanceAuthorizationResponse(String subject) {
        try {
            final List<String> content = List.of(buildProtectedIssuanceAuthorizationTrustStatement(subject));
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
