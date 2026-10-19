package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.ConfigurationOverride;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.CreateCredentialOfferRequest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialOfferMetadataDto;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.gen.issuer.model.StatusListUpdate;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletProfile;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.google.gson.JsonParser;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockserver.model.HttpRequest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.Map;
import java.util.List;
import java.net.URI;
import java.util.regex.Pattern;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockserver.model.HttpRequest.request;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.HSM)
@Slf4j
@EnabledIfSystemProperty(
        named = "hsm",
        matches = "true",
        disabledReason = "HSM tests require -Dhsm=true so SoftHSM is injected only when explicitly requested."
)
class IssuerHSMTest extends BaseTest {

    private static final String STATUS_REGISTRY_UPDATE_PATH =
            "/api/v2/status/business-entities/[^/]+/status-list-entries/";
    private static final String INITIAL_HSM_KEY_ID = "01";
    private static final String ROTATED_HSM_KEY_ID = "02";
    private static final String HSM_KEY_PIN = "1234";

    @Test
    @XrayTest(
            key = "EIDOMNI-1419",
            summary = "Credential Issuer signs a batch with its default HSM key and the Verifier accepts every presentation",
            description = """
                    Given a Credential Issuer using the default SoftHSM key.
                    When the Wallet collects a batch and presents every Credential.
                    Then each Credential verifies only with the default key and each verification reaches SUCCESS.
                    Spec: OID4VCI 1.0 section 8.3; OID4VP 1.0 section 8.6; Swiss anchor profile, JWT Validation.
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    void hsmSetupTest() throws Exception {
        // Given
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId,
                subjectClaims);
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        // Then
        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.ISSUED);
        for (String credential : batchEntry.getIssuedCredentials()) {
            final SignedJWT jwt = SignedJWT.parse(credential.split("~", -1)[0]);
            assertThat(jwt.getHeader().getKeyID())
                    .isEqualTo(issuerConfig.getIssuerAssertKeyId());
            assertThat(isSignedByHsmKey(jwt, INITIAL_HSM_KEY_ID))
                    .isTrue();
            assertThat(isSignedByHsmKey(jwt, ROTATED_HSM_KEY_ID))
                    .isFalse();
        }

        // When
        for (int i = 0; i < batchEntry.getIssuedCredentials().size(); i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL()
                    .createManagementResponse();
            final RequestObject verificationDetails = wallet
                    .getVerificationRequestObject(verification.getVerificationDeeplink());
            verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
            final String presentation = batchEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            wallet.respondToVerification(verificationDetails, presentation);
            // Then
            verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
        }
    }

    @ParameterizedTest(name = "key_pin={0}")
    @NullAndEmptySource
    @ValueSource(strings = HSM_KEY_PIN)
    @XrayTest(
            key = "EIDOMNI-1420",
            summary = "Credential Issuer signs every Credential with the override HSM key with an optional key PIN",
            description = """
                    Given a Credential Offer with an alternate HSM key and its matching verification method.
                    When the Wallet collects the batch with a missing, empty or supplied key_pin override.
                    Then every Credential advertises the alternate kid, verifies only with that key and issuance becomes ISSUED.
                    Spec: Issuer management ConfigurationOverride; OID4VCI 1.0 section 8.3; Swiss anchor profile, JWT Validation.
                    """)
    @Tag(ReportingTags.UCI_C1)
    @Tag(ReportingTags.EDGE_CASE)
    void credentialIssuance_whenHsmKeyIsOverridden_thenEveryCredentialUsesOverrideKey(final String keyPin)
            throws Exception {
        // Given
        wallet.setProfile(WalletProfile.swiss());
        final Map<String, Object> claims = CredentialSubjectFixtures.completeEmployeeProfile();
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredential(new CreateCredentialOfferRequest()
                .metadataCredentialSupportedId(List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT))
                .credentialSubjectData(claims)
                .credentialMetadata(new CredentialOfferMetadataDto().deferred(false))
                .offerValiditySeconds(86400)
                .statusLists(List.of(issuerManager.getStatusList().getStatusRegistryUrl()))
                .configurationOverride(new ConfigurationOverride()
                        .verificationMethod(issuerConfig.getIssuerAuthKeyId())
                        .keyId(ROTATED_HSM_KEY_ID)
                        .keyPin(keyPin)));

        // When
        final WalletBatchEntry entry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        // Then
        SdJwtBatchAssert.assertThat(entry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .allHaveExactlyInAnyOrderDisclosures(claims);
        for (String credential : entry.getIssuedCredentials()) {
            final SignedJWT jwt = SignedJWT.parse(credential.split("~", -1)[0]);
            assertThat(jwt.getHeader().getAlgorithm())
                    .isEqualTo(JWSAlgorithm.ES256);
            assertThat(jwt.getHeader().getKeyID())
                    .isEqualTo(issuerConfig.getIssuerAuthKeyId());
            assertThat(isSignedByHsmKey(jwt, ROTATED_HSM_KEY_ID))
                    .isTrue();
            assertThat(isSignedByHsmKey(jwt, INITIAL_HSM_KEY_ID))
                    .isFalse();
        }
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.ISSUED);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1421",
            summary = "Credential Issuer keeps its default HSM key after issuing with an override",
            description = """
                    Given a default offer and a separate offer selecting the alternate HSM key.
                    When the Wallet collects the override offer before the default offer in the same issuer runtime.
                    Then the default batch still verifies only with the default key and both issuances become ISSUED.
                    Spec: Issuer management ConfigurationOverride, scope limited to the created entity.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    void credentialIssuance_whenOverrideIsUsed_thenDefaultOfferKeepsItsOwnKey() throws Exception {
        // Given
        wallet.setProfile(WalletProfile.swiss());
        final CredentialWithDeeplinkResponse defaultOffer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final CredentialWithDeeplinkResponse overrideOffer = issuerManager.createCredential(new CreateCredentialOfferRequest()
                .metadataCredentialSupportedId(List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT))
                .credentialSubjectData(CredentialSubjectFixtures.completeEmployeeProfile())
                .credentialMetadata(new CredentialOfferMetadataDto().deferred(false))
                .offerValiditySeconds(86400)
                .statusLists(List.of(issuerManager.getStatusList().getStatusRegistryUrl()))
                .configurationOverride(new ConfigurationOverride()
                        .verificationMethod(issuerConfig.getIssuerAuthKeyId())
                        .keyId(ROTATED_HSM_KEY_ID)));

        // When
        final WalletBatchEntry overrideEntry = wallet.collectOffer(toUri(overrideOffer.getOfferDeeplink()));
        final WalletBatchEntry defaultEntry = wallet.collectOffer(toUri(defaultOffer.getOfferDeeplink()));

        // Then
        assertThat(overrideEntry.getIssuedCredentials())
                .hasSize(CredentialConfigurationFixtures.BATCH_SIZE);
        assertThat(defaultEntry.getIssuedCredentials())
                .hasSize(CredentialConfigurationFixtures.BATCH_SIZE);
        for (WalletBatchEntry entry : List.of(overrideEntry, defaultEntry)) {
            final boolean overridden = entry == overrideEntry;
            for (String credential : entry.getIssuedCredentials()) {
                final SignedJWT jwt = SignedJWT.parse(credential.split("~", -1)[0]);
                assertThat(jwt.getHeader().getKeyID())
                        .isEqualTo(overridden ? issuerConfig.getIssuerAuthKeyId() : issuerConfig.getIssuerAssertKeyId());
                assertThat(isSignedByHsmKey(jwt, ROTATED_HSM_KEY_ID))
                        .isEqualTo(overridden);
                assertThat(isSignedByHsmKey(jwt, INITIAL_HSM_KEY_ID))
                        .isEqualTo(!overridden);
            }
        }
        issuerManager.verifyStatus(overrideOffer.getManagementId(), CredentialStatusType.ISSUED);
        issuerManager.verifyStatus(defaultOffer.getManagementId(), CredentialStatusType.ISSUED);
    }

    @ParameterizedTest(name = "override={0}")
    @ValueSource(booleans = {false, true})
    @XrayTest(
            key = "EIDOMNI-1422",
            summary = "Credential Issuer signs tenant metadata with the selected HSM key",
            description = """
                    Given a default Credential Offer or one selecting the alternate HSM key.
                    When the Wallet requests the offer tenant's signed Credential Issuer Metadata.
                    Then the metadata has the expected type, subject and kid and verifies only with the selected key.
                    Spec: OID4VCI 1.0 section 12.2.3; Issuer management ConfigurationOverride.
                    """)
    @Tag(ReportingTags.UCI_M1)
    @Tag(ReportingTags.HAPPY_PATH)
    void signedIssuerMetadata_whenHsmIdentityIsSelected_thenSignatureMatchesTheTenantKey(final boolean overridden)
            throws Exception {
        // Given
        wallet.setProfile(WalletProfile.swiss());
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredential(new CreateCredentialOfferRequest()
                .metadataCredentialSupportedId(List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT))
                .credentialSubjectData(CredentialSubjectFixtures.completeEmployeeProfile())
                .credentialMetadata(new CredentialOfferMetadataDto().deferred(false))
                .offerValiditySeconds(86400)
                .statusLists(List.of(issuerManager.getStatusList().getStatusRegistryUrl()))
                .configurationOverride(overridden ? new ConfigurationOverride()
                        .verificationMethod(issuerConfig.getIssuerAuthKeyId())
                        .keyId(ROTATED_HSM_KEY_ID) : null));
        final WalletBatchEntry entry = wallet.prepareOffer(toUri(offer.getOfferDeeplink()));
        final URI metadataUri = UriComponentsBuilder
                .fromUri(wallet.getIssuerContext().getContextualizedUri(entry.getIssuerUri()))
                .pathSegment(".well-known", "openid-credential-issuer")
                .build().toUri();

        // When
        final var response = restClient.get().uri(metadataUri)
                .header(HttpHeaders.ACCEPT, "application/jwt")
                .retrieve().toEntity(String.class);
        final SignedJWT jwt = SignedJWT.parse(response.getBody());

        // Then
        assertThat(response.getStatusCode().value())
                .isEqualTo(200);
        assertThat(jwt.getHeader().getType().toString())
                .isEqualTo("openidvci-issuer-metadata+jwt");
        assertThat(jwt.getHeader().getAlgorithm())
                .isEqualTo(JWSAlgorithm.ES256);
        assertThat(jwt.getHeader().getKeyID())
                .isEqualTo(overridden ? issuerConfig.getIssuerAuthKeyId() : issuerConfig.getIssuerAssertKeyId());
        assertThat(jwt.getJWTClaimsSet().getSubject())
                .isEqualTo(entry.getIssuerUri().toString());
        assertThat(isSignedByHsmKey(jwt, ROTATED_HSM_KEY_ID))
                .isEqualTo(overridden);
        assertThat(isSignedByHsmKey(jwt, INITIAL_HSM_KEY_ID))
                .isEqualTo(!overridden);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1423",
            summary = "Credential Issuer retains the HSM key override throughout deferred issuance",
            description = """
                    Given a deferred Credential Offer selecting the alternate HSM key.
                    When the Wallet obtains a transaction_id and collects the Credentials after the offer becomes READY.
                    Then every Credential verifies only with the persisted override key and issuance becomes ISSUED.
                    Spec: OID4VCI 1.0 section 9; Issuer management ConfigurationOverride.
                    """)
    @Tag(ReportingTags.UCI_C3)
    @Tag(ReportingTags.HAPPY_PATH)
    void deferredIssuance_whenHsmKeyIsOverridden_thenCollectionKeepsTheOverrideKey() throws Exception {
        // Given
        wallet.setProfile(WalletProfile.swiss());
        final Map<String, Object> claims = CredentialSubjectFixtures.completeEmployeeProfile();
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredential(new CreateCredentialOfferRequest()
                .metadataCredentialSupportedId(List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT))
                .credentialSubjectData(claims)
                .credentialMetadata(new CredentialOfferMetadataDto().deferred(true))
                .offerValiditySeconds(86400)
                .statusLists(List.of(issuerManager.getStatusList().getStatusRegistryUrl()))
                .configurationOverride(new ConfigurationOverride()
                        .verificationMethod(issuerConfig.getIssuerAuthKeyId())
                        .keyId(ROTATED_HSM_KEY_ID)));
        final WalletBatchEntry entry = wallet.collectTransactionIdFromDeferredOffer(toUri(offer.getOfferDeeplink()));
        assertThat(entry.getTransactionId())
                .isNotNull();
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.DEFERRED);

        // When
        issuerManager.updateCredentialForDeferredFlowRequestCreation(offer.getManagementId(), claims);
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.READY);
        final var response = wallet.getCredentialFromTransactionId(entry);

        // Then
        assertThat(response.getStatus())
                .isEqualTo(200);
        SdJwtBatchAssert.assertThat(entry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .allHaveExactlyInAnyOrderDisclosures(claims);
        for (String credential : entry.getIssuedCredentials()) {
            final SignedJWT jwt = SignedJWT.parse(credential.split("~", -1)[0]);
            assertThat(jwt.getHeader().getKeyID())
                    .isEqualTo(issuerConfig.getIssuerAuthKeyId());
            assertThat(isSignedByHsmKey(jwt, ROTATED_HSM_KEY_ID))
                    .isTrue();
            assertThat(isSignedByHsmKey(jwt, INITIAL_HSM_KEY_ID))
                    .isFalse();
        }
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.ISSUED);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1424",
            summary = "Credential Issuer rejects an unknown override HSM key without issuing with its default key",
            description = """
                    Given a valid Credential Offer whose management override selects a nonexistent HSM key.
                    When the Wallet sends a valid Credential Request.
                    Then the request fails, the Wallet receives no Credential and the offer is not ISSUED.
                    Deviation: the Business Issuer selects an HSM key absent from the token.
                    Spec: Issuer management ConfigurationOverride; fail-closed signing invariant, exact HTTP error mapping Unknown.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    void credentialIssuance_whenOverrideKeyDoesNotExist_thenNoCredentialIsIssued() {
        // Given
        wallet.setProfile(WalletProfile.swiss());
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredential(new CreateCredentialOfferRequest()
                .metadataCredentialSupportedId(List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT))
                .credentialSubjectData(CredentialSubjectFixtures.completeEmployeeProfile())
                .credentialMetadata(new CredentialOfferMetadataDto().deferred(false))
                .offerValiditySeconds(86400)
                .statusLists(List.of(issuerManager.getStatusList().getStatusRegistryUrl()))
                .configurationOverride(new ConfigurationOverride().keyId("missing-hsm-credential-key")));
        final WalletBatchEntry entry = wallet.prepareOffer(toUri(offer.getOfferDeeplink()));

        // When
        final RestClientResponseException error = assertThrows(RestClientResponseException.class,
                () -> wallet.postCredentialRequest(entry));

        // Then
        assertThat(error.getStatusCode().isError())
                .isTrue();
        assertThat(entry.getIssuedCredentials())
                .isEmpty();
        assertThat(issuerManager.getStatusById(offer.getManagementId()).getStatus())
                .isNotEqualTo(CredentialStatusType.ISSUED);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-831",
            summary = "Issuer updates HSM-backed status list with configuration override key",
            description = """
                    This test validates that the Business Issuer management API uses the ConfigurationOverride
                    from a status-list update request when publishing the HSM-backed status list to the registry.
                    """
    )
    @Tag(ReportingTags.UCI_C2)
    @Tag(ReportingTags.HAPPY_PATH)
    void statusListUpdate_withHsmConfigurationOverride_thenPublishesWithOverrideKey() throws Exception {
        // Given
        final StatusList statusList = issuerManager.createStatusList(10000, 2,
                new ConfigurationOverride()
                        .verificationMethod(issuerConfig.getIssuerAuthKeyId())
                        .keyId(ROTATED_HSM_KEY_ID)
                        .keyPin(HSM_KEY_PIN));
        final int updateCountBefore = countStatusRegistryUpdates(statusList);

        final StatusListUpdate updateRequest = new StatusListUpdate()
                .configurationOverride(new ConfigurationOverride()
                        .verificationMethod(issuerConfig.getIssuerAssertKeyId())
                        .keyId(INITIAL_HSM_KEY_ID)
                        .keyPin(HSM_KEY_PIN));

        // When
        final StatusList updatedStatusList = issuerManager.updateStatusListRegistryEntry(
                statusList.getId(),
                updateRequest);

        // Then
        assertThat(updatedStatusList.getId())
                .isEqualTo(statusList.getId());
        assertThat(updatedStatusList.getStatusRegistryUrl())
                .isEqualTo(statusList.getStatusRegistryUrl());

        await().untilAsserted(() -> assertThat(countStatusRegistryUpdates(statusList))
                .isGreaterThan(updateCountBefore));

        final SignedJWT publishedStatusList = parsePublishedStatusListJwt(lastStatusRegistryUpdate(statusList));
        assertThat(publishedStatusList.getHeader().getKeyID())
                .isEqualTo(issuerConfig.getIssuerAssertKeyId());
        assertThat(isSignedByHsmKey(publishedStatusList, INITIAL_HSM_KEY_ID))
                .as("status list update should be signed with the rotated HSM key from ConfigurationOverride")
                .isTrue();
        assertThat(isSignedByHsmKey(publishedStatusList, ROTATED_HSM_KEY_ID))
                .as("status list update should not keep using the creation/static HSM key")
                .isFalse();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1425",
            summary = "Credential Issuer signs a default status list with the HSM key advertised by its kid",
            description = """
                    Given a Credential Issuer with separate default HSM keys for Credentials and status lists.
                    When the Business Issuer creates a status list without configuration_override.
                    Then the registry receives a token signed by the configured status key matching the advertised kid.
                    Spec: Swiss VC profile, Token Status List section 5.1; Swiss anchor profile, JWT Validation.
                    """)
    @Tag(ReportingTags.UCI_C2)
    @Tag(ReportingTags.HAPPY_PATH)
    void statusListCreation_whenNoOverrideIsProvided_thenDefaultStatusKeyMatchesItsKid() throws Exception {
        // Given / When
        final StatusList statusList = issuerManager.createStatusList(10000, 2);
        await().untilAsserted(() -> assertThat(countStatusRegistryUpdates(statusList))
                .isPositive());
        final SignedJWT jwt = parsePublishedStatusListJwt(lastStatusRegistryUpdate(statusList));

        // Then
        assertThat(jwt.getHeader().getKeyID())
                .isEqualTo(issuerConfig.getIssuerAuthKeyId());
        assertThat(isSignedByHsmKey(jwt, ROTATED_HSM_KEY_ID))
                .isTrue();
        assertThat(isSignedByHsmKey(jwt, INITIAL_HSM_KEY_ID))
                .isFalse();
        assertThat(jwt.verify(new ECDSAVerifier(signingKeyFromDidLog(
                issuerConfig.getIssuerDidLog(), issuerConfig.getIssuerAuthKeyId()))))
                .isTrue();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1426",
            summary = "Credential Issuer publishes a new status list with its override HSM key without a key PIN",
            description = """
                    Given a status-list creation request selecting the alternate HSM key and matching verification method.
                    When the Business Issuer creates the list without key_pin.
                    Then the v2 registry receives a statuslist+jwt signed only with the alternate key and the correct kid.
                    Spec: Swiss VC profile, Token Status List section 5.1; Issuer management ConfigurationOverride.
                    """)
    @Tag(ReportingTags.UCI_C2)
    @Tag(ReportingTags.HAPPY_PATH)
    void statusListCreation_whenHsmKeyIsOverriddenWithoutPin_thenPublishesWithOverrideKey() throws Exception {
        // Given / When
        final StatusList statusList = issuerManager.createStatusList(10000, 2, new ConfigurationOverride()
                .verificationMethod(issuerConfig.getIssuerAssertKeyId())
                .keyId(INITIAL_HSM_KEY_ID));
        await().untilAsserted(() -> assertThat(countStatusRegistryUpdates(statusList))
                .isPositive());
        final SignedJWT jwt = parsePublishedStatusListJwt(lastStatusRegistryUpdate(statusList));

        // Then
        assertThat(jwt.getHeader().getAlgorithm())
                .isEqualTo(JWSAlgorithm.ES256);
        assertThat(jwt.getHeader().getType().toString())
                .isEqualTo("statuslist+jwt");
        assertThat(jwt.getHeader().getKeyID())
                .isEqualTo(issuerConfig.getIssuerAssertKeyId());
        assertThat(jwt.getJWTClaimsSet().getSubject())
                .isEqualTo(statusList.getStatusRegistryUrl());
        assertThat(jwt.getJWTClaimsSet().getExpirationTime().toInstant())
                .isAfter(java.time.Instant.now());
        assertThat(isSignedByHsmKey(jwt, INITIAL_HSM_KEY_ID))
                .isTrue();
        assertThat(isSignedByHsmKey(jwt, ROTATED_HSM_KEY_ID))
                .isFalse();
    }

    @ParameterizedTest(name = "empty configuration_override={0}")
    @ValueSource(booleans = {false, true})
    @XrayTest(
            key = "EIDOMNI-1427",
            summary = "Credential Issuer preserves a stored HSM status-list override when an update supplies no replacement",
            description = """
                    Given a status list created with the alternate HSM key and matching verification method.
                    When the Business Issuer updates it with an absent or empty configuration_override.
                    Then publication still uses the stored override key and verification method.
                    Spec: Issuer StatusListOrchestrator.updateStatusList contract, persisted non-null field merge.
                    """)
    @Tag(ReportingTags.UCI_C2)
    @Tag(ReportingTags.EDGE_CASE)
    void statusListUpdate_whenOverrideIsAbsentOrEmpty_thenPreservesStoredKey(final boolean emptyOverride)
            throws Exception {
        // Given
        final StatusList statusList = issuerManager.createStatusList(10000, 2, new ConfigurationOverride()
                .verificationMethod(issuerConfig.getIssuerAssertKeyId())
                .keyId(INITIAL_HSM_KEY_ID));
        final int before = countStatusRegistryUpdates(statusList);

        // When
        issuerManager.updateStatusListRegistryEntry(statusList.getId(), new StatusListUpdate()
                .configurationOverride(emptyOverride ? new ConfigurationOverride() : null));
        await().untilAsserted(() -> assertThat(countStatusRegistryUpdates(statusList))
                .isGreaterThan(before));
        final SignedJWT jwt = parsePublishedStatusListJwt(lastStatusRegistryUpdate(statusList));

        // Then
        assertThat(jwt.getHeader().getKeyID())
                .isEqualTo(issuerConfig.getIssuerAssertKeyId());
        assertThat(isSignedByHsmKey(jwt, INITIAL_HSM_KEY_ID))
                .isTrue();
        assertThat(isSignedByHsmKey(jwt, ROTATED_HSM_KEY_ID))
                .isFalse();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1428",
            summary = "Credential Issuer retains the stored status-list key and verification method during a partial HSM override",
            description = """
                    Given a status list selecting the alternate HSM key.
                    When an update supplies only key_pin and omits key_id and verification_method.
                    Then the omitted fields retain their persisted values and publication verifies only with the alternate key.
                    Spec: Issuer StatusListOrchestrator.updateStatusList contract, persisted non-null field merge.
                    """)
    @Tag(ReportingTags.UCI_C2)
    @Tag(ReportingTags.EDGE_CASE)
    void statusListUpdate_whenOnlyKeyPinIsProvided_thenRetainsStoredKeyAndVerificationMethod() throws Exception {
        // Given
        final StatusList statusList = issuerManager.createStatusList(10000, 2, new ConfigurationOverride()
                .verificationMethod(issuerConfig.getIssuerAssertKeyId())
                .keyId(INITIAL_HSM_KEY_ID));
        final int before = countStatusRegistryUpdates(statusList);

        // When
        issuerManager.updateStatusListRegistryEntry(statusList.getId(), new StatusListUpdate()
                .configurationOverride(new ConfigurationOverride().keyPin(HSM_KEY_PIN)));
        await().untilAsserted(() -> assertThat(countStatusRegistryUpdates(statusList))
                .isGreaterThan(before));
        final SignedJWT jwt = parsePublishedStatusListJwt(lastStatusRegistryUpdate(statusList));

        // Then
        assertThat(jwt.getHeader().getKeyID())
                .isEqualTo(issuerConfig.getIssuerAssertKeyId());
        assertThat(isSignedByHsmKey(jwt, INITIAL_HSM_KEY_ID))
                .isTrue();
        assertThat(isSignedByHsmKey(jwt, ROTATED_HSM_KEY_ID))
                .isFalse();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1429",
            summary = "Credential Issuer rejects an unknown status-list HSM key and preserves the last valid override",
            description = """
                    Given a status list successfully published with the alternate HSM key.
                    When an update selects a nonexistent key and a later update omits configuration_override.
                    Then the invalid update sends no registry PUT and the later publication still uses the original key and kid.
                    Deviation: the Business Issuer selects an HSM key absent from the token.
                    Spec: Issuer management ConfigurationOverride; atomic update invariant, exact HTTP error mapping Unknown.
                    """)
    @Tag(ReportingTags.UCI_C2)
    @Tag(ReportingTags.EDGE_CASE)
    void statusListUpdate_whenOverrideKeyDoesNotExist_thenDoesNotPublishOrPersistInvalidKey() throws Exception {
        // Given
        final StatusList statusList = issuerManager.createStatusList(10000, 2, new ConfigurationOverride()
                .verificationMethod(issuerConfig.getIssuerAssertKeyId())
                .keyId(INITIAL_HSM_KEY_ID));
        final int before = countStatusRegistryUpdates(statusList);

        // When
        final RestClientResponseException error = assertThrows(RestClientResponseException.class,
                () -> issuerManager.updateStatusListRegistryEntry(statusList.getId(), new StatusListUpdate()
                        .configurationOverride(new ConfigurationOverride().keyId("missing-hsm-status-key"))));

        // Then
        assertThat(error.getStatusCode().isError())
                .isTrue();
        assertThat(countStatusRegistryUpdates(statusList))
                .isEqualTo(before);

        // When
        issuerManager.updateStatusListRegistryEntry(statusList.getId(), new StatusListUpdate());
        await().untilAsserted(() -> assertThat(countStatusRegistryUpdates(statusList))
                .isGreaterThan(before));
        final SignedJWT jwt = parsePublishedStatusListJwt(lastStatusRegistryUpdate(statusList));

        // Then
        assertThat(jwt.getHeader().getKeyID())
                .isEqualTo(issuerConfig.getIssuerAssertKeyId());
        assertThat(isSignedByHsmKey(jwt, INITIAL_HSM_KEY_ID))
                .isTrue();
        assertThat(isSignedByHsmKey(jwt, ROTATED_HSM_KEY_ID))
                .isFalse();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1430",
            summary = "Credential Issuer isolates HSM key rotation between status lists",
            description = """
                    Given two status lists created with the initial HSM key.
                    When the first list rotates to the alternate key and the second is republished unchanged.
                    Then each publication verifies only with its own list's key and advertises the matching kid.
                    Spec: Issuer management ConfigurationOverride, scope limited to the created entity.
                    """)
    @Tag(ReportingTags.UCI_C2)
    @Tag(ReportingTags.EDGE_CASE)
    void statusListUpdate_whenOneListRotates_thenAnotherListKeepsItsOwnKey() throws Exception {
        // Given
        final StatusList rotatedList = issuerManager.createStatusList(10000, 2, new ConfigurationOverride()
                .verificationMethod(issuerConfig.getIssuerAssertKeyId())
                .keyId(INITIAL_HSM_KEY_ID));
        final StatusList unchangedList = issuerManager.createStatusList(10000, 2, new ConfigurationOverride()
                .verificationMethod(issuerConfig.getIssuerAssertKeyId())
                .keyId(INITIAL_HSM_KEY_ID));
        final int rotatedBefore = countStatusRegistryUpdates(rotatedList);
        final int unchangedBefore = countStatusRegistryUpdates(unchangedList);

        // When
        issuerManager.updateStatusListRegistryEntry(rotatedList.getId(), new StatusListUpdate()
                .configurationOverride(new ConfigurationOverride()
                        .verificationMethod(issuerConfig.getIssuerAuthKeyId())
                        .keyId(ROTATED_HSM_KEY_ID)));
        issuerManager.updateStatusListRegistryEntry(unchangedList.getId(), new StatusListUpdate());
        await().untilAsserted(() -> {
            assertThat(countStatusRegistryUpdates(rotatedList))
                    .isGreaterThan(rotatedBefore);
            assertThat(countStatusRegistryUpdates(unchangedList))
                    .isGreaterThan(unchangedBefore);
        });

        // Then
        for (StatusList statusList : List.of(rotatedList, unchangedList)) {
            final boolean rotated = statusList == rotatedList;
            final SignedJWT jwt = parsePublishedStatusListJwt(lastStatusRegistryUpdate(statusList));
            assertThat(jwt.getHeader().getKeyID())
                    .isEqualTo(rotated ? issuerConfig.getIssuerAuthKeyId() : issuerConfig.getIssuerAssertKeyId());
            assertThat(isSignedByHsmKey(jwt, ROTATED_HSM_KEY_ID))
                    .isEqualTo(rotated);
            assertThat(isSignedByHsmKey(jwt, INITIAL_HSM_KEY_ID))
                    .isEqualTo(!rotated);
        }
    }

    private int countStatusRegistryUpdates(final StatusList statusList) {
        return mockServerClient.retrieveRecordedRequests(statusRegistryUpdateRequest(statusList)).length;
    }

    private HttpRequest lastStatusRegistryUpdate(final StatusList statusList) {
        final HttpRequest[] requests = mockServerClient.retrieveRecordedRequests(statusRegistryUpdateRequest(statusList));
        assertThat(requests)
                .isNotEmpty();
        return requests[requests.length - 1];
    }

    private HttpRequest statusRegistryUpdateRequest(final StatusList statusList) {
        final String path = URI.create(statusList.getStatusRegistryUrl()).getPath();
        final String registryId = path.substring(path.lastIndexOf('/') + 1).replaceFirst("\\.jwt$", "");
        return request()
                .withMethod("PUT")
                .withPath(STATUS_REGISTRY_UPDATE_PATH + Pattern.quote(registryId));
    }

    private SignedJWT parsePublishedStatusListJwt(final HttpRequest httpRequest) throws ParseException {
        final String body = httpRequest.getBodyAsString();
        assertThat(body).isNotBlank();

        if (body.contains(".")) {
            return SignedJWT.parse(body);
        }

        final String decodedBody = new String(Base64.getDecoder().decode(body), StandardCharsets.UTF_8);
        return SignedJWT.parse(decodedBody);
    }

    private ECKey signingKeyFromDidLog(final String didLog, final String keyId) throws ParseException {
        final var methods = JsonParser.parseString(didLog).getAsJsonObject()
                .getAsJsonObject("state").getAsJsonArray("verificationMethod");
        for (var method : methods) {
            final var candidate = method.getAsJsonObject();
            if (keyId.equals(candidate.get("id").getAsString())) {
                return JWK.parse(candidate.getAsJsonObject("publicKeyJwk").toString()).toECKey();
            }
        }
        throw new IllegalArgumentException("No public verification method published for " + keyId);
    }

    private boolean isSignedByHsmKey(final SignedJWT jwt, final String keyId) throws IOException, JOSEException {
        final String certificateResourcePath = "softhsm/keys/%s-cert.pem".formatted(keyId);
        try (InputStream inputStream = getClass().getResourceAsStream("/" + certificateResourcePath)) {
            assertThat(inputStream)
                    .as("HSM public certificate should be available: %s", certificateResourcePath)
                    .isNotNull();
            final String certificatePem = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
            return jwt.verify(new ECDSAVerifier(JWK.parseFromPEMEncodedX509Cert(certificatePem).toECKey()));
        }
    }
}
