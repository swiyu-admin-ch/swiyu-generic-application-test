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
import ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementRouteSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementRouteSupport.IDENTITY_TRUST_STATEMENT_PATH;
import static ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementRouteSupport.PROTECTED_ISSUANCE_AUTHORIZATION_PATH;
import static ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementRouteSupport.PROTECTED_VCT;
import static ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementRouteSupport.TP2_PROFILE_VERSION;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.awaitility.Awaitility.await;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
public class IssuerTrustStatementTest extends BaseTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().findAndRegisterModules();
    private static final Duration CACHED_TRUST_STATEMENT_LIFETIME = Duration.ofMinutes(4);
    private static final Duration SHORT_TRUST_STATEMENT_LIFETIME = Duration.ofSeconds(3);
    private static final Duration EXPIRY_WAIT_CUSHION = Duration.ofSeconds(6);
    private static final String PROTECTED_CREDENTIAL_CONFIGURATION_ID =
            CredentialConfigurationFixtures.UNIVERSITY_EXAMPLE_HIGH_KEY_ATTESTATION_REQUIRED_SD_JWT;
    private static final String PROTECTED_ISSUANCE_AUTHORIZATION_TRUST_STATEMENT =
            "protected_issuance_authorization_trust_statement";
    private static final String IDENTITY_TRUST_STATEMENT_TYPE = "swiyu-identity-trust-statement+jwt";
    private static final String PROTECTED_ISSUANCE_AUTHORIZATION_TRUST_STATEMENT_TYPE =
            "swiyu-protected-issuance-authorization-trust-statement+jwt";

    @Test
    @XrayTest(
            key = "EIDOMNI-965",
            summary = "Issuer metadata includes cached idTS and piaTS",
            description = """
                    Given a protected credential offer with an issuer DID override and valid TP2 registry responses.
                    When the wallet fetches OID4VCI issuer metadata twice.
                    Then metadata contains valid idTS and matching piaTS, and the second fetch reuses cached statements.
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(issuer = {ImageTags.STABLE}, reason = "The TP2.0 is not available yet")
    void tenantIssuerMetadata_whenTrustStatementsCached_thenInjectsStatementsAndReusesCache() {
        final Tp2TrustStatementRouteSupport tp2Routes = tp2Routes();

        // Given
        tp2Routes.registerIssuerSuccess(CACHED_TRUST_STATEMENT_LIFETIME);
        final ConfigurationOverride issuerOverride = uniqueIssuerOverride();
        final WalletBatchEntry walletEntry = walletEntryWithProtectedOffer(issuerOverride);

        try {
            final int idTsCallsBefore = tp2Routes.identityTrustStatementRequests();
            final int piaTsCallsBefore = tp2Routes.protectedIssuanceAuthorizationRequests();

            // When
            final IssuerMetadata firstMetadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final String firstIdTs = firstMetadata.getCredentialIssuerIdentityTrustStatement();
            final String firstPiaTs = protectedIssuanceAuthorizationTrustStatement(walletEntry.getIssuerMetadataRaw());

            // Then
            assertIdentityTrustStatement(firstIdTs, issuerOverride.getIssuerDid());
            assertProtectedIssuanceAuthorizationTrustStatement(firstPiaTs, issuerOverride.getIssuerDid(), PROTECTED_VCT);
            assertThat(tp2Routes.identityTrustStatementRequests()).isEqualTo(idTsCallsBefore + 1);
            assertThat(tp2Routes.protectedIssuanceAuthorizationRequests()).isEqualTo(piaTsCallsBefore + 1);

            // When
            final IssuerMetadata repeatedMetadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final String repeatedPiaTs = protectedIssuanceAuthorizationTrustStatement(walletEntry.getIssuerMetadataRaw());

            // Then
            assertThat(repeatedMetadata.getCredentialIssuerIdentityTrustStatement()).isEqualTo(firstIdTs);
            assertThat(repeatedPiaTs).isEqualTo(firstPiaTs);
            assertThat(tp2Routes.identityTrustStatementRequests()).isEqualTo(idTsCallsBefore + 1);
            assertThat(tp2Routes.protectedIssuanceAuthorizationRequests()).isEqualTo(piaTsCallsBefore + 1);
        } finally {
            tp2Routes.restoreDefaults(issuerConfig, verifierConfig, trustConfig, OBJECT_MAPPER);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-972",
            summary = "Issuer metadata refreshes expired TP2 trust statements",
            description = """
                    Given short-lived issuer idTS and piaTS values.
                    When the wallet fetches metadata after the earliest statement expiration.
                    Then the issuer refetches TP2 statements and metadata contains fresh JWT values.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(issuer = {ImageTags.STABLE}, reason = "The TP2.0 is not available yet")
    void tenantIssuerMetadata_whenTrustStatementExpReached_thenRefetchesTrustStatements() {
        final Tp2TrustStatementRouteSupport tp2Routes = tp2Routes();

        // Given
        tp2Routes.registerIssuerSuccess(SHORT_TRUST_STATEMENT_LIFETIME);
        final ConfigurationOverride issuerOverride = uniqueIssuerOverride();
        final WalletBatchEntry walletEntry = walletEntryWithProtectedOffer(issuerOverride);

        try {
            final int idTsCallsBefore = tp2Routes.identityTrustStatementRequests();
            final int piaTsCallsBefore = tp2Routes.protectedIssuanceAuthorizationRequests();

            // When
            final IssuerMetadata firstMetadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final String firstIdTs = firstMetadata.getCredentialIssuerIdentityTrustStatement();
            final String firstPiaTs = protectedIssuanceAuthorizationTrustStatement(walletEntry.getIssuerMetadataRaw());

            // Then
            assertIdentityTrustStatement(firstIdTs, issuerOverride.getIssuerDid());
            assertProtectedIssuanceAuthorizationTrustStatement(firstPiaTs, issuerOverride.getIssuerDid(), PROTECTED_VCT);

            // When
            awaitTrustStatementsExpired(firstIdTs, firstPiaTs);
            final IssuerMetadata refreshedMetadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final String refreshedPiaTs = protectedIssuanceAuthorizationTrustStatement(walletEntry.getIssuerMetadataRaw());

            // Then
            assertThat(refreshedMetadata.getCredentialIssuerIdentityTrustStatement())
                    .as("Expired idTS must be refetched")
                    .isNotBlank()
                    .isNotEqualTo(firstIdTs);
            assertThat(refreshedPiaTs)
                    .as("Expired piaTS must be refetched")
                    .isNotBlank()
                    .isNotEqualTo(firstPiaTs);
            assertThat(tp2Routes.identityTrustStatementRequests()).isEqualTo(idTsCallsBefore + 2);
            assertThat(tp2Routes.protectedIssuanceAuthorizationRequests()).isEqualTo(piaTsCallsBefore + 2);
        } finally {
            tp2Routes.restoreDefaults(issuerConfig, verifierConfig, trustConfig, OBJECT_MAPPER);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-973",
            summary = "Issuer metadata suppresses immediate retry during TP2 negative-cache window",
            description = """
                    Given the Trust Registry temporarily returns errors for idTS and piaTS.
                    When the wallet fetches issuer metadata twice in immediate succession.
                    Then metadata omits TP2 statements and the second fetch does not retry during the negative-cache window.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(issuer = {ImageTags.STABLE}, reason = "The TP2.0 is not available yet")
    void tenantIssuerMetadata_whenTrustStatementFetchFails_thenNegativeCacheSuppressesImmediateRetry() {
        final Tp2TrustStatementRouteSupport tp2Routes = tp2Routes();

        // Given
        tp2Routes.registerIssuerTransientErrorThenSuccess(CACHED_TRUST_STATEMENT_LIFETIME);
        final ConfigurationOverride issuerOverride = uniqueIssuerOverride();
        final WalletBatchEntry walletEntry = walletEntryWithProtectedOffer(issuerOverride);
        final int idTsCallsBefore = tp2Routes.identityTrustStatementRequests();
        final int piaTsCallsBefore = tp2Routes.protectedIssuanceAuthorizationRequests();

        try {
            // When
            final IssuerMetadata firstMetadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final String firstPiaTs = protectedIssuanceAuthorizationTrustStatement(walletEntry.getIssuerMetadataRaw());

            // Then
            assertThat(firstMetadata.getCredentialIssuerIdentityTrustStatement()).isNull();
            assertThat(firstPiaTs).isNull();
            assertThat(tp2Routes.identityTrustStatementRequests()).isEqualTo(idTsCallsBefore + 1);
            assertThat(tp2Routes.protectedIssuanceAuthorizationRequests()).isEqualTo(piaTsCallsBefore + 1);

            // When
            final IssuerMetadata repeatedMetadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final String repeatedPiaTs = protectedIssuanceAuthorizationTrustStatement(walletEntry.getIssuerMetadataRaw());

            // Then
            assertThat(repeatedMetadata.getCredentialIssuerIdentityTrustStatement()).isNull();
            assertThat(repeatedPiaTs).isNull();
            assertThat(tp2Routes.identityTrustStatementRequests()).isEqualTo(idTsCallsBefore + 1);
            assertThat(tp2Routes.protectedIssuanceAuthorizationRequests()).isEqualTo(piaTsCallsBefore + 1);
        } finally {
            tp2Routes.restoreDefaults(issuerConfig, verifierConfig, trustConfig, OBJECT_MAPPER);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-996",
            summary = "Issuer metadata cache is scoped by effective issuer DID",
            description = """
                    Given two protected credential offers using different issuer DID overrides.
                    When the wallet fetches metadata for both offers.
                    Then each metadata response contains statements whose subject matches its own issuer DID.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(issuer = {ImageTags.STABLE}, reason = "The TP2.0 is not available yet")
    void tenantIssuerMetadata_whenIssuerDidChanges_thenTrustStatementCacheIsSubjectScoped() {
        final Tp2TrustStatementRouteSupport tp2Routes = tp2Routes();

        // Given
        tp2Routes.registerIssuerSuccess(CACHED_TRUST_STATEMENT_LIFETIME);
        final ConfigurationOverride firstIssuer = uniqueIssuerOverride();
        final ConfigurationOverride secondIssuer = uniqueIssuerOverride();
        final WalletBatchEntry firstWalletEntry = walletEntryWithProtectedOffer(firstIssuer);
        final WalletBatchEntry secondWalletEntry = walletEntryWithProtectedOffer(secondIssuer);

        try {
            // When
            final IssuerMetadata firstMetadata = wallet.getIssuerWellKnownMetadata(firstWalletEntry);
            final String firstIdTs = firstMetadata.getCredentialIssuerIdentityTrustStatement();
            final String firstPiaTs = protectedIssuanceAuthorizationTrustStatement(firstWalletEntry.getIssuerMetadataRaw());
            final IssuerMetadata secondMetadata = wallet.getIssuerWellKnownMetadata(secondWalletEntry);
            final String secondIdTs = secondMetadata.getCredentialIssuerIdentityTrustStatement();
            final String secondPiaTs = protectedIssuanceAuthorizationTrustStatement(secondWalletEntry.getIssuerMetadataRaw());

            // Then
            assertIdentityTrustStatement(firstIdTs, firstIssuer.getIssuerDid());
            assertProtectedIssuanceAuthorizationTrustStatement(firstPiaTs, firstIssuer.getIssuerDid(), PROTECTED_VCT);
            assertIdentityTrustStatement(secondIdTs, secondIssuer.getIssuerDid());
            assertProtectedIssuanceAuthorizationTrustStatement(secondPiaTs, secondIssuer.getIssuerDid(), PROTECTED_VCT);
            assertThat(secondIdTs).isNotEqualTo(firstIdTs);
            assertThat(secondPiaTs).isNotEqualTo(firstPiaTs);
        } finally {
            tp2Routes.restoreDefaults(issuerConfig, verifierConfig, trustConfig, OBJECT_MAPPER);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-995",
            summary = "Issuer metadata omits non-matching piaTS without invalidating idTS",
            description = """
                    Given the Trust Registry returns an idTS and a piaTS for a different VCT.
                    When the wallet fetches issuer metadata.
                    Then metadata should keep idTS, omit piaTS, and avoid repeated registry calls.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    void tenantIssuerMetadata_whenPiaTsVctDoesNotMatch_thenDoesNotInvalidateTrustStatementCache() {
        final Tp2TrustStatementRouteSupport tp2Routes = tp2Routes();

        // Given
        final ConfigurationOverride issuerOverride = uniqueIssuerOverride();
        final WalletBatchEntry walletEntry = walletEntryWithProtectedOffer(issuerOverride);
        tp2Routes.registerIssuerSuccess(CACHED_TRUST_STATEMENT_LIFETIME, PROTECTED_VCT + "/mismatch");

        try {
            // When
            final IssuerMetadata metadata = wallet.getIssuerWellKnownMetadata(walletEntry);

            // Then
            assertIdentityTrustStatement(metadata.getCredentialIssuerIdentityTrustStatement(), issuerOverride.getIssuerDid());
            assertThat(protectedIssuanceAuthorizationTrustStatement(walletEntry.getIssuerMetadataRaw())).isNull();
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

    private WalletBatchEntry walletEntryWithProtectedOffer(ConfigurationOverride configurationOverride) {
        final CredentialWithDeeplinkResponse offer = createCredentialOffer(configurationOverride);
        final WalletBatchEntry walletEntry = wallet.createWalletBatchEntry();
        walletEntry.receiveDeepLinkAndValidateIt(toUri(offer.getOfferDeeplink()));
        return walletEntry;
    }

    private ConfigurationOverride uniqueIssuerOverride() {
        final String issuerDid = swiyuDidVariant(issuerConfig.getIssuerDid());

        return new ConfigurationOverride()
                .issuerDid(issuerDid)
                .verificationMethod(issuerDid + "#assert-key-01");
    }

    private String swiyuDidVariant(String did) {
        final int lastColon = did.lastIndexOf(':');
        return did.substring(0, lastColon + 1) + UUID.randomUUID();
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

    private String protectedIssuanceAuthorizationTrustStatement(JsonNode metadata) {
        final JsonNode node = metadata.path("credential_configurations_supported")
                .path(PROTECTED_CREDENTIAL_CONFIGURATION_ID)
                .path(PROTECTED_ISSUANCE_AUTHORIZATION_TRUST_STATEMENT);

        return node.isMissingNode() || node.isNull() ? null : node.asText();
    }

    private void assertIdentityTrustStatement(String jwt, String expectedSubject) {
        try {
            assertThat(jwt).as("Metadata must include idTS").isNotBlank();
            final SignedJWT statement = SignedJWT.parse(jwt);
            final JWTClaimsSet claimsSet = statement.getJWTClaimsSet();

            assertTrustStatementHeader(statement, IDENTITY_TRUST_STATEMENT_TYPE);
            assertThat(claimsSet.getSubject()).isEqualTo(expectedSubject);
            assertThat(claimsSet.getIssueTime()).isNotNull();
            assertThat(claimsSet.getExpirationTime()).isNotNull();
            assertThat(claimsSet.getJSONObjectClaim("status")).containsKey("status_list");
            assertThat(claimsSet.getStringClaim("entity_name")).isNotBlank();
            assertThat(claimsSet.getBooleanClaim("is_state_actor")).isTrue();
            assertThat(claimsSet.getClaim("registry_ids")).isInstanceOf(List.class);
        } catch (ParseException e) {
            throw new IllegalStateException("Cannot parse idTS from issuer metadata", e);
        }
    }

    private void assertProtectedIssuanceAuthorizationTrustStatement(String jwt, String expectedSubject, String expectedVct) {
        try {
            assertThat(jwt).as("Protected metadata must include piaTS").isNotBlank();
            final SignedJWT statement = SignedJWT.parse(jwt);
            final JWTClaimsSet claimsSet = statement.getJWTClaimsSet();

            assertTrustStatementHeader(statement, PROTECTED_ISSUANCE_AUTHORIZATION_TRUST_STATEMENT_TYPE);
            assertThat(claimsSet.getSubject()).isEqualTo(expectedSubject);
            assertThat(claimsSet.getJWTID()).isNotBlank();
            assertThat(claimsSet.getIssueTime()).isNotNull();
            assertThat(claimsSet.getExpirationTime()).isNotNull();
            assertThat(claimsSet.getJSONObjectClaim("status")).containsKey("status_list");

            @SuppressWarnings("unchecked")
            final Map<String, Object> canIssue = (Map<String, Object>) claimsSet.getClaim("can_issue");
            assertThat(canIssue).containsEntry("vct", expectedVct);
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
