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
import ch.admin.bj.swiyu.swiyu_test_wallet.config.TrustConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustConfigFactory;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementAlgorithm;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementRouteSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.net.URI;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementRouteSupport.IDENTITY_TRUST_STATEMENT_PATH;
import static ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementRouteSupport.PROTECTED_ISSUANCE_AUTHORIZATION_PATH;
import static ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementRouteSupport.PROTECTED_VCT;
import static ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementRouteSupport.IssuerTrustStatementTarget.IDENTITY;
import static ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementRouteSupport.IssuerTrustStatementTarget.PROTECTED_ISSUANCE_AUTHORIZATION;
import static ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementRouteSupport.TP2_PROFILE_VERSION;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.awaitility.Awaitility.await;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.CACHED)
public class IssuerTrustStatementTest extends BaseTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
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
    private final Map<Tp2TrustStatementAlgorithm, TrustConfig> agileTrustConfigs =
            new EnumMap<>(Tp2TrustStatementAlgorithm.class);

    private enum InvalidSignatureScenario {
        TAMPERED_PAYLOAD,
        WRONG_KEY
    }

    @ParameterizedTest(name = "[{index}] Trust Statements signed with {0}")
    @EnumSource(
            value = Tp2TrustStatementAlgorithm.class,
            names = {"ES256", "ED25519"}
    )
    @XrayTest(
            key = "EIDOMNI-1237",
            summary = "Issuer accepts ES256 and Ed25519 Trust Statement signatures",
            description = """
                    Given the trusted TP2 registry publishes a P-256 or Ed25519 assertion key.
                    When it returns correctly signed idTS and piaTS values using either allowed algorithm.
                    Then the Generic Issuer validates and injects both Trust Statements into issuer metadata.
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(issuer = {ImageTags.STABLE}, reason = "EIDOMNI-1050 is not available yet")
    void tenantIssuerMetadata_whenTrustStatementsUseAllowedAlgorithm_thenAcceptsBothAlgorithms(
            Tp2TrustStatementAlgorithm algorithm) {
        final Tp2TrustStatementRouteSupport tp2Routes = tp2Routes(algorithm);

        // Given
        tp2Routes.registerIssuerSuccess(CACHED_TRUST_STATEMENT_LIFETIME);

        try {
            final ConfigurationOverride issuerOverride = uniqueIssuerOverride();
            final WalletBatchEntry walletEntry = walletEntryWithProtectedOffer(issuerOverride);

            // When
            final IssuerMetadata metadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final String piaTs = protectedIssuanceAuthorizationTrustStatement(walletEntry.getIssuerMetadataRaw());

            // Then
            assertIdentityTrustStatement(
                    metadata.getCredentialIssuerIdentityTrustStatement(),
                    issuerOverride.getIssuerDid(),
                    algorithm
            );
            assertProtectedIssuanceAuthorizationTrustStatement(
                    piaTs,
                    issuerOverride.getIssuerDid(),
                    PROTECTED_VCT,
                    algorithm
            );
        } finally {
            tp2Routes.restoreDefaults(issuerConfig, verifierConfig, trustConfig, OBJECT_MAPPER);
        }
    }

    @ParameterizedTest(name = "[{index}] {0} / {1} / {2}")
    @MethodSource("invalidTrustStatementSignatures")
    @XrayTest(
            key = "EIDOMNI-1238",
            summary = "Issuer strictly rejects invalid ES256 and Ed25519 Trust Statement signatures",
            description = """
                    Given either an idTS or a piaTS whose payload was modified after signing or whose signature was made
                    with a private key not published under the trusted kid, while the other statement remains valid.
                    When the signature uses ES256 or Ed25519.
                    Then the Generic Issuer rejects the invalid statement and still injects the independently valid one.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(issuer = {ImageTags.STABLE}, reason = "EIDOMNI-1050 is not available yet")
    void tenantIssuerMetadata_whenTrustStatementSignatureInvalid_thenRejectsForBothAlgorithms(
            Tp2TrustStatementAlgorithm algorithm,
            InvalidSignatureScenario invalidSignatureScenario,
            Tp2TrustStatementRouteSupport.IssuerTrustStatementTarget invalidTarget) {
        final Tp2TrustStatementRouteSupport tp2Routes = tp2Routes(algorithm);

        // Given
        switch (invalidSignatureScenario) {
            case TAMPERED_PAYLOAD ->
                    tp2Routes.registerIssuerTamperedPayload(CACHED_TRUST_STATEMENT_LIFETIME, invalidTarget);
            case WRONG_KEY -> tp2Routes.registerIssuerWrongKey(CACHED_TRUST_STATEMENT_LIFETIME, invalidTarget);
        }

        try {
            final ConfigurationOverride issuerOverride = uniqueIssuerOverride();
            final WalletBatchEntry walletEntry = walletEntryWithProtectedOffer(issuerOverride);

            // When
            final IssuerMetadata metadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final String idTs = metadata.getCredentialIssuerIdentityTrustStatement();
            final String piaTs = protectedIssuanceAuthorizationTrustStatement(walletEntry.getIssuerMetadataRaw());

            // Then
            if (invalidTarget == IDENTITY) {
                assertThat(idTs).as("Invalid idTS must never be injected").isNull();
                assertProtectedIssuanceAuthorizationTrustStatement(
                        piaTs,
                        issuerOverride.getIssuerDid(),
                        PROTECTED_VCT,
                        algorithm
                );
            } else {
                assertIdentityTrustStatement(idTs, issuerOverride.getIssuerDid(), algorithm);
                assertThat(piaTs).as("Invalid piaTS must never be injected").isNull();
            }
        } finally {
            tp2Routes.restoreDefaults(issuerConfig, verifierConfig, trustConfig, OBJECT_MAPPER);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1239",
            summary = "Issuer rejects a valid Trust Statement signed with an unapproved algorithm",
            description = """
                    Given the trusted TP2 registry DID publishes an Ed25519 assertion key and returns cryptographically
                    valid idTS and piaTS values using the deprecated EdDSA alg identifier.
                    When the Generic Issuer validates the statements.
                    Then it rejects them because only ES256 and Ed25519 are in the EIDOMNI-1050 allowlist.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(issuer = {ImageTags.STABLE}, reason = "EIDOMNI-1050 is not available yet")
    void tenantIssuerMetadata_whenTrustStatementAlgorithmNotAllowed_thenRejectsWithoutAlgorithmConfusion() {
        final Tp2TrustStatementRouteSupport tp2Routes = tp2Routes(Tp2TrustStatementAlgorithm.EDDSA_LEGACY);

        // Given
        tp2Routes.registerIssuerSuccess(CACHED_TRUST_STATEMENT_LIFETIME);

        try {
            final ConfigurationOverride issuerOverride = uniqueIssuerOverride();
            final WalletBatchEntry walletEntry = walletEntryWithProtectedOffer(issuerOverride);

            // When
            final IssuerMetadata metadata = wallet.getIssuerWellKnownMetadata(walletEntry);

            // Then
            assertThat(metadata.getCredentialIssuerIdentityTrustStatement())
                    .as("A valid signature with a non-allowlisted algorithm must be rejected")
                    .isNull();
            assertThat(protectedIssuanceAuthorizationTrustStatement(walletEntry.getIssuerMetadataRaw()))
                    .as("The algorithm policy must also protect piaTS validation")
                    .isNull();
        } finally {
            tp2Routes.restoreDefaults(issuerConfig, verifierConfig, trustConfig, OBJECT_MAPPER);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1240",
            summary = "Issuer rejects unsecured alg none Trust Statements",
            description = """
                    Given the TP2 registry response contains idTS and piaTS values with alg=none and no signature.
                    When the Generic Issuer validates the statements.
                    Then it rejects them and does not inject their claims into issuer metadata.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(issuer = {ImageTags.STABLE}, reason = "EIDOMNI-1050 is not available yet")
    void tenantIssuerMetadata_whenTrustStatementUsesAlgorithmNone_thenStrictlyRejects() {
        final Tp2TrustStatementRouteSupport tp2Routes = tp2Routes();

        // Given
        tp2Routes.registerIssuerAlgorithmNone(CACHED_TRUST_STATEMENT_LIFETIME);

        try {
            final ConfigurationOverride issuerOverride = uniqueIssuerOverride();
            final WalletBatchEntry walletEntry = walletEntryWithProtectedOffer(issuerOverride);

            // When
            final IssuerMetadata metadata = wallet.getIssuerWellKnownMetadata(walletEntry);

            // Then
            assertThat(metadata.getCredentialIssuerIdentityTrustStatement()).isNull();
            assertThat(protectedIssuanceAuthorizationTrustStatement(walletEntry.getIssuerMetadataRaw())).isNull();
        } finally {
            tp2Routes.restoreDefaults(issuerConfig, verifierConfig, trustConfig, OBJECT_MAPPER);
        }
    }

    private static Stream<Arguments> invalidTrustStatementSignatures() {
        return Stream.of(Tp2TrustStatementAlgorithm.ES256, Tp2TrustStatementAlgorithm.ED25519)
                .flatMap(algorithm -> Stream.of(InvalidSignatureScenario.values())
                        .flatMap(scenario -> Stream.of(IDENTITY, PROTECTED_ISSUANCE_AUTHORIZATION)
                                .map(target -> Arguments.of(algorithm, scenario, target))));
    }

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
            final int idTsCallsBefore = tp2Routes.identityTrustStatementRequests(issuerOverride.getIssuerDid());
            final int piaTsCallsBefore = tp2Routes.protectedIssuanceAuthorizationRequests(issuerOverride.getIssuerDid());

            // When
            final IssuerMetadata firstMetadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final String firstIdTs = firstMetadata.getCredentialIssuerIdentityTrustStatement();
            final String firstPiaTs = protectedIssuanceAuthorizationTrustStatement(walletEntry.getIssuerMetadataRaw());

            // Then
            assertIdentityTrustStatement(firstIdTs, issuerOverride.getIssuerDid());
            assertProtectedIssuanceAuthorizationTrustStatement(firstPiaTs, issuerOverride.getIssuerDid(), PROTECTED_VCT);
            assertThat(tp2Routes.identityTrustStatementRequests(issuerOverride.getIssuerDid()))
                    .isEqualTo(idTsCallsBefore + 1);
            assertThat(tp2Routes.protectedIssuanceAuthorizationRequests(issuerOverride.getIssuerDid()))
                    .isEqualTo(piaTsCallsBefore + 1);

            // When
            final IssuerMetadata repeatedMetadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final String repeatedPiaTs = protectedIssuanceAuthorizationTrustStatement(walletEntry.getIssuerMetadataRaw());

            // Then
            assertThat(repeatedMetadata.getCredentialIssuerIdentityTrustStatement()).isEqualTo(firstIdTs);
            assertThat(repeatedPiaTs).isEqualTo(firstPiaTs);
            assertThat(tp2Routes.identityTrustStatementRequests(issuerOverride.getIssuerDid()))
                    .isEqualTo(idTsCallsBefore + 1);
            assertThat(tp2Routes.protectedIssuanceAuthorizationRequests(issuerOverride.getIssuerDid()))
                    .isEqualTo(piaTsCallsBefore + 1);
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
            final int idTsCallsBefore = tp2Routes.identityTrustStatementRequests(issuerOverride.getIssuerDid());
            final int piaTsCallsBefore = tp2Routes.protectedIssuanceAuthorizationRequests(issuerOverride.getIssuerDid());

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
            assertThat(tp2Routes.identityTrustStatementRequests(issuerOverride.getIssuerDid()))
                    .isEqualTo(idTsCallsBefore + 2);
            assertThat(tp2Routes.protectedIssuanceAuthorizationRequests(issuerOverride.getIssuerDid()))
                    .isEqualTo(piaTsCallsBefore + 2);
        } finally {
            tp2Routes.restoreDefaults(issuerConfig, verifierConfig, trustConfig, OBJECT_MAPPER);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-973",
            summary = "Issuer retries TP2 trust statements after a transient registry outage",
            description = """
                    Given issuer A previously received valid statements and the Trust Registry returns one transient
                    error for issuer B's idTS and piaTS before recovering.
                    When the wallet fetches issuer B's metadata three times in immediate succession.
                    Then the first response does not reuse issuer A's statements, the second retries and recovers, and
                    the third reuses issuer B's validated statements from cache.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    void tenantIssuerMetadata_whenTrustStatementFetchFails_thenRetriesAndCachesRecovery() {
        final Tp2TrustStatementRouteSupport tp2Routes = tp2Routes();

        // Given
        tp2Routes.registerIssuerSuccess(CACHED_TRUST_STATEMENT_LIFETIME);
        try {
            final ConfigurationOverride previousIssuerOverride = uniqueIssuerOverride();
            final WalletBatchEntry previousIssuerEntry = walletEntryWithOffer(
                    previousIssuerOverride,
                    CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
            );
            final IssuerMetadata previousIssuerMetadata = wallet.getIssuerWellKnownMetadata(previousIssuerEntry);
            assertIdentityTrustStatement(
                    previousIssuerMetadata.getCredentialIssuerIdentityTrustStatement(),
                    previousIssuerOverride.getIssuerDid()
            );
            assertProtectedIssuanceAuthorizationTrustStatement(
                    protectedIssuanceAuthorizationTrustStatement(previousIssuerEntry.getIssuerMetadataRaw()),
                    previousIssuerOverride.getIssuerDid(),
                    PROTECTED_VCT
            );

            tp2Routes.registerIssuerTransientErrorThenSuccess(CACHED_TRUST_STATEMENT_LIFETIME);
            final ConfigurationOverride issuerOverride = uniqueIssuerOverride();
            final WalletBatchEntry walletEntry = walletEntryWithProtectedOffer(issuerOverride);
            final int idTsCallsBefore = tp2Routes.identityTrustStatementRequests(issuerOverride.getIssuerDid());
            final int piaTsCallsBefore = tp2Routes.protectedIssuanceAuthorizationRequests(issuerOverride.getIssuerDid());

            // When
            final IssuerMetadata firstMetadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final String firstPiaTs = protectedIssuanceAuthorizationTrustStatement(walletEntry.getIssuerMetadataRaw());

            // Then
            assertThat(firstMetadata.getCredentialIssuerIdentityTrustStatement()).isNull();
            assertThat(firstPiaTs).isNull();
            assertThat(tp2Routes.identityTrustStatementRequests(issuerOverride.getIssuerDid()))
                    .isEqualTo(idTsCallsBefore + 1);
            assertThat(tp2Routes.protectedIssuanceAuthorizationRequests(issuerOverride.getIssuerDid()))
                    .isEqualTo(piaTsCallsBefore + 1);

            // When
            final IssuerMetadata recoveredMetadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final String recoveredIdTs = recoveredMetadata.getCredentialIssuerIdentityTrustStatement();
            final String recoveredPiaTs = protectedIssuanceAuthorizationTrustStatement(
                    walletEntry.getIssuerMetadataRaw()
            );

            // Then
            assertThat(tp2Routes.identityTrustStatementRequests(issuerOverride.getIssuerDid()))
                    .isEqualTo(idTsCallsBefore + 2);
            assertThat(tp2Routes.protectedIssuanceAuthorizationRequests(issuerOverride.getIssuerDid()))
                    .isEqualTo(piaTsCallsBefore + 2);
            assertIdentityTrustStatement(recoveredIdTs, issuerOverride.getIssuerDid());
            assertProtectedIssuanceAuthorizationTrustStatement(
                    recoveredPiaTs,
                    issuerOverride.getIssuerDid(),
                    PROTECTED_VCT
            );

            // When
            final IssuerMetadata cachedMetadata = wallet.getIssuerWellKnownMetadata(walletEntry);
            final String cachedPiaTs = protectedIssuanceAuthorizationTrustStatement(
                    walletEntry.getIssuerMetadataRaw()
            );

            // Then
            assertThat(cachedMetadata.getCredentialIssuerIdentityTrustStatement()).isEqualTo(recoveredIdTs);
            assertThat(cachedPiaTs).isEqualTo(recoveredPiaTs);
            assertThat(tp2Routes.identityTrustStatementRequests(issuerOverride.getIssuerDid()))
                    .isEqualTo(idTsCallsBefore + 2);
            assertThat(tp2Routes.protectedIssuanceAuthorizationRequests(issuerOverride.getIssuerDid()))
                    .isEqualTo(piaTsCallsBefore + 2);
        } finally {
            tp2Routes.restoreDefaults(issuerConfig, verifierConfig, trustConfig, OBJECT_MAPPER);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1101",
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
        return tp2Routes(Tp2TrustStatementAlgorithm.ES256);
    }

    private Tp2TrustStatementRouteSupport tp2Routes(Tp2TrustStatementAlgorithm signatureAlgorithm) {
        final TrustConfig algorithmTrustConfig = trustConfigFor(signatureAlgorithm);
        return new Tp2TrustStatementRouteSupport(
                mockServerClient,
                issuerConfig,
                verifierConfig,
                algorithmTrustConfig,
                OBJECT_MAPPER,
                signatureAlgorithm
        );
    }

    private TrustConfig trustConfigFor(Tp2TrustStatementAlgorithm algorithm) {
        if (algorithm == Tp2TrustStatementAlgorithm.ES256) {
            return trustConfig;
        }
        return agileTrustConfigs.computeIfAbsent(algorithm, ignored -> {
            final URI didRegistryEntry = URI.create(
                    "https://mockserver:1080/api/v1/did/" + UUID.randomUUID()
            );
            final TrustConfig agileTrustConfig =
                    Tp2TrustConfigFactory.createEd25519TrustConfig(didRegistryEntry);
            mockServerClientConfig.replaceDidLog(
                    agileTrustConfig.getTrustDid(),
                    agileTrustConfig.getTrustDidLog()
            );
            return agileTrustConfig;
        });
    }

    private WalletBatchEntry walletEntryWithProtectedOffer(ConfigurationOverride configurationOverride) {
        return walletEntryWithOffer(configurationOverride, PROTECTED_CREDENTIAL_CONFIGURATION_ID);
    }

    private WalletBatchEntry walletEntryWithOffer(ConfigurationOverride configurationOverride,
                                                  String credentialConfigurationId) {
        final CredentialWithDeeplinkResponse offer = createCredentialOffer(
                configurationOverride,
                credentialConfigurationId
        );
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

    private CredentialWithDeeplinkResponse createCredentialOffer(ConfigurationOverride configurationOverride,
                                                                 String credentialConfigurationId) {
        final StatusList statusList = createStatusList(configurationOverride);
        final CreateCredentialOfferRequest offerRequest = new CreateCredentialOfferRequest()
                .metadataCredentialSupportedId(List.of(credentialConfigurationId))
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
        assertIdentityTrustStatement(jwt, expectedSubject, Tp2TrustStatementAlgorithm.ES256);
    }

    private void assertIdentityTrustStatement(String jwt,
                                              String expectedSubject,
                                              Tp2TrustStatementAlgorithm algorithm) {
        try {
            assertThat(jwt).as("Metadata must include idTS").isNotBlank();
            final SignedJWT statement = SignedJWT.parse(jwt);
            final JWTClaimsSet claimsSet = statement.getJWTClaimsSet();

            assertTrustStatementHeader(statement, IDENTITY_TRUST_STATEMENT_TYPE, algorithm);
            assertThat(claimsSet.getSubject()).isEqualTo(expectedSubject);
            assertThat(claimsSet.getJWTID()).isNotBlank();
            assertThat(UUID.fromString(claimsSet.getJWTID()).version()).isEqualTo(4);
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
        assertProtectedIssuanceAuthorizationTrustStatement(
                jwt,
                expectedSubject,
                expectedVct,
                Tp2TrustStatementAlgorithm.ES256
        );
    }

    private void assertProtectedIssuanceAuthorizationTrustStatement(String jwt,
                                                                    String expectedSubject,
                                                                    String expectedVct,
                                                                    Tp2TrustStatementAlgorithm algorithm) {
        try {
            assertThat(jwt).as("Protected metadata must include piaTS").isNotBlank();
            final SignedJWT statement = SignedJWT.parse(jwt);
            final JWTClaimsSet claimsSet = statement.getJWTClaimsSet();

            assertTrustStatementHeader(
                    statement,
                    PROTECTED_ISSUANCE_AUTHORIZATION_TRUST_STATEMENT_TYPE,
                    algorithm
            );
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

    private void assertTrustStatementHeader(SignedJWT statement,
                                            String expectedType,
                                            Tp2TrustStatementAlgorithm algorithm) {
        assertThat(statement.getHeader().getAlgorithm().getName()).isEqualTo(expectedJoseAlgorithm(algorithm));
        assertThat(statement.getHeader().getKeyID()).isEqualTo(expectedTrustKeyId(algorithm));
        assertThat(statement.getHeader().getType().toString()).isEqualTo(expectedType);
        assertThat(statement.getHeader().getCustomParam("profile_version")).isEqualTo(TP2_PROFILE_VERSION);
    }

    private String expectedJoseAlgorithm(Tp2TrustStatementAlgorithm algorithm) {
        return switch (algorithm) {
            case ES256 -> "ES256";
            case ED25519 -> "Ed25519";
            case EDDSA_LEGACY -> "EdDSA";
        };
    }

    private String expectedTrustKeyId(Tp2TrustStatementAlgorithm algorithm) {
        return switch (algorithm) {
            case ES256 -> trustConfig.getTrustAssertKeyId();
            case ED25519, EDDSA_LEGACY -> trustConfigFor(algorithm).getTrustEd25519AssertKeyId();
        };
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
