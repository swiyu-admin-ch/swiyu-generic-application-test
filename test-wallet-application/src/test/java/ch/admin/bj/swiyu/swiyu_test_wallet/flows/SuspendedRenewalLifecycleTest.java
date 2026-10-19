package ch.admin.bj.swiyu.swiyu_test_wallet.flows;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CreateCredentialOfferRequest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseVerifiers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_response.CredentialResponseAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.UseWallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockserver.matchers.MatchType;
import org.mockserver.matchers.TimeToLive;
import org.mockserver.matchers.Times;
import org.mockserver.mock.Expectation;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;
import tools.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.InflaterInputStream;

import static ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result.CredentialEvaluationAssert.assertEvaluation;
import static ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result.TokenStatusListValues.REVOKED;
import static ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result.TokenStatusListValues.SUSPENDED;
import static ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result.TokenStatusListValues.VALID;
import static ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result.VerificationHttpStatusAssert.assertWalletAndManagementRespondOk;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.DEFAULT_CREDENTIAL_ID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.mockserver.model.JsonBody.json;

/** Exercises experimental suspended renewal across the Business Issuer, Wallet and Verifier boundaries. */
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.RENEWAL_PERMISSIVE_EXPERIMENTAL)
@UseVerifiers(VerifierVariant.DEFAULT)
@UseWallet(dpop = true, encryption = true, signedMetadata = true)
@Tag(ReportingTags.UCI_I1)
@Tag(ReportingTags.UCV_O2)
@Tag(ReportingTags.EDGE_CASE)
class SuspendedRenewalLifecycleTest extends BaseTest {

    @Test
    @XrayTest(key = "EIDOMNI-XXX",
            summary = "Credential Issuer preserves suspension across repeated renewals and subsequent family status changes",
            description = """
                    Given experimental suspended renewal enabled and an issued batch that the Business Issuer suspends.
                    When the Wallet renews twice, then the Business Issuer reactivates and finally revokes the family.
                    Then every initial and renewed credential is evaluated as SUSPENDED, VALID and REVOKED respectively,
                    and renewal never reactivates the family or loses a generation from its management record.
                    Renewed batches use the Business Issuer's updated subject data; the initial batch stays unchanged.
                    Deviation: the Wallet presents suspended and revoked credentials to exercise Verifier rejection.
                    Spec: EIDOMNI-1085 and EIDOMNI-1086; Swiss issuance profile sections 14.5 and 14.6;
                    Swiss VC profile section 7.1 (Status Types Values); OID4VP 1.0 section 8.6 (VP Token Validation).
                    """)
    void credentialRenewal_whenSuspendedFamilyIsRenewedTwice_thenAllGenerationsFollowLaterStatusChanges() {
        // Given
        useComponents(issuer(IssuerVariant.RENEWAL_PERMISSIVE_EXPERIMENTAL), verifier(VerifierVariant.DEFAULT));
        final var initialSubject = CredentialSubjectFixtures.completeEmployeeProfile();
        initialSubject.put(CredentialSubjectFixtures.TEXT_OPTIONAL_CLAIM_KEY, "Previous role");
        final var offer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                initialSubject);
        final var initialEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final var initialCredentials = List.copyOf(initialEntry.getIssuedCredentials());
        final int batchSize = initialEntry.getIssuerMetadata().getBatchCredentialIssuance().getBatchSize();
        assertThat(initialCredentials)
                .hasSize(batchSize);
        SdJwtBatchAssert.assertThat(initialCredentials)
                .allHaveExactlyInAnyOrderDisclosures(initialSubject);
        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.SUSPENDED);
        final var secondEntry = initialEntry.duplicate();
        final var thirdEntry = initialEntry.duplicate();

        // When: both generations use the same family authorization and fresh proofs.
        for (final var renewalEntry : List.of(secondEntry, thirdEntry)) {
            CredentialResponseAssert.assertThat(wallet.renewedCredentials(renewalEntry))
                    .hasCode(200)
                    .hasNotTransactionId()
                    .isResponseEncrypted();
            SdJwtBatchAssert.assertThat(renewalEntry.getIssuedCredentials())
                    .hasBatchSize(batchSize)
                    .areUnique()
                    .haveUniqueHolderBindingKeys()
                    .haveUniqueStatusListIndexes()
                    .haveDisclosuresBoundToPayloadDigests()
                    .allHaveExactlyInAnyOrderDisclosures(CredentialSubjectFixtures.completeEmployeeProfile());
            assertThat(issuerManager.getCredentialById(offer.getManagementId()).getStatus())
                    .as("Renewing a suspended family must not reactivate it")
                    .isEqualTo(CredentialStatusType.SUSPENDED);
        }

        // Then: the Business Issuer controls the status of every credential in every generation.
        final var managementAfterRenewal = issuerManager.getCredentialById(offer.getManagementId());
        assertThat(managementAfterRenewal.getCredentialOffers())
                .hasSize(3);
        assertThat(managementAfterRenewal.getRenewalRequestCount())
                .isEqualTo(2);
        assertThat(managementAfterRenewal.getRenewalResponseCount())
                .isEqualTo(2);
        assertThat(initialEntry.getIssuedCredentials())
                .containsExactlyElementsOf(initialCredentials);
        assertThat(thirdEntry.getIssuedCredentials())
                .doesNotContainAnyElementsOf(secondEntry.getIssuedCredentials());
        final var allCredentials = List.of(initialEntry, secondEntry, thirdEntry).stream()
                .flatMap(batch -> batch.heldCredentials().stream())
                .toList();
        assertThat(allCredentials.size())
                .isEqualTo(batchSize * 3);

        for (final var familyStatus : List.of(UpdateCredentialStatusRequestType.SUSPENDED,
                UpdateCredentialStatusRequestType.ISSUED, UpdateCredentialStatusRequestType.REVOKED)) {
            if (familyStatus != UpdateCredentialStatusRequestType.SUSPENDED) {
                issuerManager.updateState(offer.getManagementId(), familyStatus);
            }
            final int expectedStatus = switch (familyStatus) {
                case SUSPENDED -> SUSPENDED;
                case ISSUED -> VALID;
                default -> REVOKED;
            };
            for (int index = 0; index < allCredentials.size(); index++) {
                final var verification = verifierManager.verificationRequest()
                        .acceptedIssuerDid(issuerConfig.getIssuerDid())
                        .withUniversityDCQL(true)
                        .encrypted()
                        .createManagementResponse();
                final var requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
                final String presentation = allCredentials.get(index).present(requestObject.getClientId(), requestObject.getNonce());
                final var result = assertWalletAndManagementRespondOk(
                        () -> wallet.respondToVerificationWithVpTokens(requestObject, List.of(presentation)),
                        verifierManager, verification.getId());
                assertThat(result.getState())
                        .as("Credential %s under family status %s", index, familyStatus)
                        .isEqualTo(expectedStatus == VALID ? VerificationStatus.SUCCESS : VerificationStatus.FAILED);
                assertEvaluation(result, DEFAULT_CREDENTIAL_ID, expectedStatus == VALID, expectedStatus);
            }
            final var management = issuerManager.getCredentialById(offer.getManagementId());
            assertThat(management.getStatus())
                    .isEqualTo(CredentialStatusType.valueOf(familyStatus.name()));
            assertThat(management.getCredentialOffers())
                    .containsExactlyInAnyOrderElementsOf(managementAfterRenewal.getCredentialOffers());
        }
    }

    @ParameterizedTest(name = "future notBefore with family status {0}")
    @EnumSource(value = UpdateCredentialStatusRequestType.class, names = {"ISSUED", "SUSPENDED"})
    // Keep the signed claims, stale-registry precondition and Verifier assertions visible together.
    @SuppressWarnings("PMD.NcssCount")
    @XrayTest(key = "EIDOMNI-XXX",
            summary = "Credential Issuer propagates Business Issuer notBefore and Verifier enforces it despite a stale Status List",
            description = """
                    Given experimental suspended renewal enabled and a Business Issuer setting credential_valid_from
                    on both initial issuance and renewal, sufficiently in the future after UTC day rounding.
                    When an issued or suspended family is renewed while the Status Registry serves an older signed list
                    in which all the initial and newly allocated indexes still have status VALID.
                    Then every initial and renewed credential has the same future rounded nbf, no later than the
                    Business Issuer's configured start, and the family retains its status.
                    The Verifier accepts a currently valid control credential, but rejects presentation of either
                    not-yet-valid generation. No automatic or randomized timestamp offset is assumed.
                    Deviation: the Wallet presents not-yet-valid credentials; the Status Registry serves a stale snapshot.
                    Spec: EIDOMNI-1087 supplied ADR decision; RFC 7519 section 4.1.5 (nbf);
                    OID4VP 1.0 section 8.6 (VP Token Validation); Swiss issuance profile sections 14.5 and 14.6;
                    Token Status List draft 20 section 4.1 (Compressed Byte Array).
                    """)
    void credentialRenewal_whenBusinessIssuerSetsFutureNotBefore_thenVerifierRejectsBothGenerationsDespiteStaleStatus(
            final UpdateCredentialStatusRequestType familyStatus) throws Exception {
        // Given: prove this issuer, Wallet and Verifier can complete a currently valid presentation.
        useComponents(issuer(IssuerVariant.RENEWAL_PERMISSIVE_EXPERIMENTAL), verifier(VerifierVariant.DEFAULT));
        final var controlOffer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                CredentialSubjectFixtures.completeEmployeeProfile());
        final var controlEntry = wallet.collectOffer(toUri(controlOffer.getOfferDeeplink()));
        final var controlVerification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(true)
                .encrypted()
                .createManagementResponse();
        final var controlRequest = wallet.getVerificationRequestObject(controlVerification.getVerificationDeeplink());
        final String controlPresentation = controlEntry.createPresentationForSdJwtIndex(0, controlRequest);
        final var controlResult = assertWalletAndManagementRespondOk(
                () -> wallet.respondToVerificationWithVpTokens(controlRequest, List.of(controlPresentation)),
                verifierManager, controlVerification.getId());
        assertThat(controlResult.getState())
                .isEqualTo(VerificationStatus.SUCCESS);
        assertEvaluation(controlResult, DEFAULT_CREDENTIAL_ID, true, VALID);

        // Two days ahead remains beyond the propagation window even around UTC midnight after rounding.
        final Instant businessStart = Instant.now().plus(2, ChronoUnit.DAYS)
                .truncatedTo(ChronoUnit.DAYS).plus(6, ChronoUnit.HOURS);
        final Instant businessEnd = businessStart.plus(7, ChronoUnit.DAYS);
        final Instant expectedNotBefore = businessStart.truncatedTo(ChronoUnit.DAYS);
        final var offer = issuerManager.createCredential(offerWithValidity(businessStart, businessEnd));
        final var initialEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final var renewedEntry = initialEntry.duplicate();
        final var issuerSignatureVerifier = new ECDSAVerifier((ECPublicKey) issuerConfig.getKeyPair().getPublic());
        final var mapper = new ObjectMapper();
        final int batchSize = initialEntry.getIssuerMetadata().getBatchCredentialIssuance().getBatchSize();
        final String statusPath = URI.create(getCurrentStatusList().getStatusRegistryUrl()).getPath();
        final URI publicStatusUri = URI.create("http://%s:%d%s".formatted(
                mockServerContainer.getHost(), mockServerContainer.getServerPort(), statusPath));
        final String staleStatusList = restClient.get().uri(publicStatusUri).retrieve().body(String.class);
        assertThat(staleStatusList)
                .isNotBlank();
        final var statusJwt = SignedJWT.parse(staleStatusList);
        assertThat(statusJwt.verify(issuerSignatureVerifier))
                .as("The propagation gap uses a correctly signed Status List Token")
                .isTrue();
        final var statusClaims = statusJwt.getJWTClaimsSet().getJSONObjectClaim("status_list");
        final int bits = ((Number) statusClaims.get("bits")).intValue();
        assertThat(bits)
                .isEqualTo(2);
        final byte[] staleStatuses;
        try (var inflater = new InflaterInputStream(new ByteArrayInputStream(
                Base64.getUrlDecoder().decode((String) statusClaims.get("lst"))))) {
            staleStatuses = inflater.readAllBytes();
        }
        final var staleExpectation = mockServerClient
                .when(request().withMethod("GET").withPath(statusPath), Times.unlimited(), TimeToLive.unlimited(), 100)
                .respond(response().withStatusCode(200).withHeader("Content-Type", "application/statuslist+jwt")
                        .withBody(staleStatusList));
        final var businessResponse = renewalWithValidity(offer.getManagementId(), businessStart, businessEnd);

        try {
            if (familyStatus == UpdateCredentialStatusRequestType.SUSPENDED) {
                issuerManager.updateState(offer.getManagementId(), familyStatus);
            }

            // When
            CredentialResponseAssert.assertThat(wallet.renewedCredentials(renewedEntry))
                    .hasCode(200)
                    .hasNotTransactionId()
                    .isResponseEncrypted();

            // Then: verify the signed claims independently of the shared builder and the request DTO.
            assertThat(expectedNotBefore)
                    .isAfter(Instant.now().plus(15, ChronoUnit.MINUTES));
            for (final WalletBatchEntry batch : List.of(initialEntry, renewedEntry)) {
                assertThat(batch.getIssuedCredentials())
                        .hasSize(batchSize);
                for (final String credential : batch.getIssuedCredentials()) {
                    final var jwt = SignedJWT.parse(credential.split("~")[0]);
                    assertThat(jwt.verify(issuerSignatureVerifier))
                            .isTrue();
                    final var claims = jwt.getJWTClaimsSet();
                    assertThat(claims.getNotBeforeTime())
                            .isNotNull();
                    assertThat(claims.getNotBeforeTime().toInstant())
                            .isEqualTo(expectedNotBefore)
                            .isBeforeOrEqualTo(businessStart)
                            .isBefore(claims.getExpirationTime().toInstant());
                    final var status = mapper.readTree(jwt.getPayload().toString())
                            .path("status").path("status_list");
                    assertThat(status.path("uri").asString())
                            .isEqualTo(getCurrentStatusList().getStatusRegistryUrl());
                    final int statusIndex = status.path("idx").intValue();
                    final int bitOffset = statusIndex * bits;
                    final int snapshotStatus = (staleStatuses[bitOffset / 8] >>> (bitOffset % 8)) & ((1 << bits) - 1);
                    assertThat(snapshotStatus)
                            .as("The stale registry would consider index %s valid without the nbf check", statusIndex)
                            .isEqualTo(VALID);
                }

                final var verification = verifierManager.verificationRequest()
                        .acceptedIssuerDid(issuerConfig.getIssuerDid())
                        .withUniversityDCQL(true)
                        .encrypted()
                        .createManagementResponse();
                final var requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
                final String presentation = batch.createPresentationForSdJwtIndex(0, requestObject);
                final var failure = assertThrows(HttpClientErrorException.class,
                        () -> wallet.respondToVerificationWithVpTokens(requestObject, List.of(presentation)));
                ApiErrorAssert.assertThat(failure)
                        .hasStatus(400)
                        .hasError("invalid_transaction_data")
                        .hasErrorCode("malformed_credential")
                        .hasErrorDescription("SD-JWT claims are not valid");
                final var result = verifierManager.getVerificationById(verification.getId());
                assertThat(result.getState())
                        .isEqualTo(VerificationStatus.FAILED);
            }
            assertThat(restClient.get().uri(publicStatusUri).retrieve().body(String.class))
                    .as("The public snapshot must remain stale throughout both presentation attempts")
                    .isEqualTo(staleStatusList);
            final var management = issuerManager.getCredentialById(offer.getManagementId());
            assertThat(management.getStatus())
                    .isEqualTo(CredentialStatusType.valueOf(familyStatus.name()));
            assertThat(management.getCredentialOffers())
                    .hasSize(2);
            assertThat(management.getRenewalResponseCount())
                    .isEqualTo(1);
        } finally {
            mockServerClient.clear(staleExpectation[0].getId());
            mockServerClient.clear(businessResponse[0].getId());
        }
    }

    private CreateCredentialOfferRequest offerWithValidity(final Instant validFrom, final Instant validUntil) {
        return new CreateCredentialOfferRequest()
                .metadataCredentialSupportedId(List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT))
                .credentialSubjectData(CredentialSubjectFixtures.completeEmployeeProfile())
                .statusLists(List.of(getCurrentStatusList().getStatusRegistryUrl()))
                .credentialValidFrom(validFrom)
                .credentialValidUntil(validUntil);
    }

    private Expectation[] renewalWithValidity(final UUID managementId, final Instant validFrom, final Instant validUntil) {
        final String body = new ObjectMapper().writeValueAsString(Map.of(
                "metadata_credential_supported_id", List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT),
                "credential_subject_data", CredentialSubjectFixtures.completeEmployeeProfile(),
                "credential_valid_from", validFrom.toString(),
                "credential_valid_until", validUntil.toString(),
                "status_lists", List.of(getCurrentStatusList().getStatusRegistryUrl())));
        return mockServerClient.when(request().withMethod("POST").withPath("/renewal")
                        .withBody(json("{\"management_id\":\"" + managementId + "\"}", MatchType.ONLY_MATCHING_FIELDS)),
                        Times.exactly(1), TimeToLive.unlimited(), 100)
                .respond(response().withStatusCode(200).withHeader("Content-Type", "application/json").withBody(body));
    }
}
