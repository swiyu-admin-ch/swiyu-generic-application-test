package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CreateCredentialOfferRequest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialOfferMetadataDto;
import ch.admin.bj.swiyu.gen.issuer.model.StatusListCreate;
import ch.admin.bj.swiyu.gen.issuer.model.StatusListCreateConfig;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseVerifiers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.StatusListTokenFixture;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.UseWallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockserver.matchers.Times;
import org.mockserver.model.HttpRequest;
import org.mockserver.matchers.TimeToLive;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

import static ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result.CredentialEvaluationAssert.assertEvaluation;
import static ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result.TokenStatusListValues.REVOKED;
import static ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result.TokenStatusListValues.VALID;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.DEFAULT_CREDENTIAL_ID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

@UseIssuers(IssuerVariant.COMPLETE)
@UseVerifiers(VerifierVariant.STATUS_LIST_CACHED)
@UseWallet(dpop = true, encryption = true, signedMetadata = true)
class VerifierStatusListCacheLifecycleE2ETest extends BaseTest {

    @Test
    @XrayTest(key = "EIDOMNI-1571",
            summary = "Verifier refreshes a cached status list and rejects a subsequently revoked credential",
            description = """
                    Given an issued Credential and a Verifier with status-list caching enabled.
                    When two presentations warm and reuse the cache, the Issuer revokes the Credential,
                    and another presentation is submitted after the configured cache lifetime.
                    Then the Verifier fetches the list again, reports REVOKED and FAILED, and preserves the earlier successful result.
                    Spec: Token Status List draft 20 §8.3 Validation Rules and §13.7 Status List Update Interval and Caching;
                    Swiss VC profile Token Status List §5.1. The cache lifetime is the Verifier configuration.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCV_O2C_CHECK_VC_STATUS_IN_REGISTRY)
    void credentialStatus_whenRevokedAfterCacheWarmup_thenRejectedAfterCacheExpiry() {
        // Given
        final IssuedCredential issued = issueCredentialOnFreshList();
        final HttpRequest statusRequest = statusRequest(issued.statusListUri());
        final int requestsBefore = statusRequests(statusRequest);
        final ManagementResponse first = present(issued.entry());
        final Instant cacheDeadline = Instant.now().plusMillis(verifierImageConfig.getStatusListCacheTtlMillis());
        assertThat(first.getState())
                .isEqualTo(VerificationStatus.SUCCESS);
        assertEvaluation(first, DEFAULT_CREDENTIAL_ID, true, VALID);
        assertThat(statusRequests(statusRequest))
                .isEqualTo(requestsBefore + 1);

        final ManagementResponse cached = present(issued.entry());
        assertThat(cached.getState())
                .isEqualTo(VerificationStatus.SUCCESS);
        assertThat(statusRequests(statusRequest))
                .as("A second presentation must exercise an actual cache hit")
                .isEqualTo(requestsBefore + 1);

        // When
        issuerManager.updateState(issued.managementId(), UpdateCredentialStatusRequestType.REVOKED);
        await()
                .atMost(Duration.ofSeconds(35))
                .until(() -> Instant.now().isAfter(cacheDeadline.plusMillis(250)));
        final int callbacksBefore = awaitStableVerifierCallbacks();
        final ManagementResponse rejected = present(issued.entry());

        // Then
        assertThat(rejected.getState())
                .isEqualTo(VerificationStatus.FAILED);
        assertEvaluation(rejected, DEFAULT_CREDENTIAL_ID, false, REVOKED);
        assertThat(statusRequests(statusRequest))
                .isEqualTo(requestsBefore + 2);
        assertThat(verifierManager.getVerificationById(first.getId()))
                .usingRecursiveComparison()
                .isEqualTo(first);
        awaitOneVerifierCallback(callbacksBefore);
        assertThat(awaitStableVerifierCallbacks())
                .isEqualTo(callbacksBefore + 1);
    }

    @Test
    @XrayTest(key = "EIDOMNI-1572",
            summary = "Verifier stops trusting a cached status list at its expiration when the registry is unavailable",
            description = """
                    Given a valid Status List Token whose exp precedes the configured cache lifetime.
                    When the Verifier caches it, the registry becomes unavailable and the token expires.
                    Then the Verifier attempts a fresh fetch, fails the verification without stale status data,
                    emits one callback and preserves the earlier successful result.
                    Spec: Token Status List draft 20 §8.3 Validation Rules; Swiss VC profile Token Status List §5.1.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCV_O2C_CHECK_VC_STATUS_IN_REGISTRY)
    void credentialStatus_whenCachedTokenExpiresAndRegistryIsUnavailable_thenRejectedWithoutStaleFallback() {
        // Given
        final IssuedCredential issued = issueCredentialOnFreshList();
        final HttpRequest statusRequest = statusRequest(issued.statusListUri());
        final String original = restClient.get()
                .uri("http://%s:%d%s".formatted(mockServerContainer.getHost(), mockServerContainer.getServerPort(),
                        URI.create(issued.statusListUri()).getPath()))
                .retrieve()
                .body(String.class);
        final Instant expiresAt = Instant.now().plusSeconds(8);
        final String token = StatusListTokenFixture.withLifetime(original, issuerConfig.getKeyPair(), expiresAt, 120);
        final AtomicBoolean unavailable = new AtomicBoolean();
        final String expectationId = mockServerClient.when(statusRequest, Times.unlimited(), TimeToLive.unlimited(), 300)
                .respond(incoming -> unavailable.get()
                        ? response().withStatusCode(503)
                        : response().withStatusCode(200)
                                .withHeader("Content-Type", "application/statuslist+jwt")
                                .withBody(token))[0].getId();
        try {
            final ManagementResponse first = present(issued.entry());
            assertThat(first.getState())
                    .isEqualTo(VerificationStatus.SUCCESS);
            final int requestsAfterWarmup = statusRequests(statusRequest);
            unavailable.set(true);
            final ManagementResponse cached = present(issued.entry());
            assertThat(cached.getState())
                    .isEqualTo(VerificationStatus.SUCCESS);
            assertThat(statusRequests(statusRequest))
                    .as("The unavailable registry is not called while its cached token is valid")
                    .isEqualTo(requestsAfterWarmup);

            // When
            await()
                    .atMost(Duration.ofSeconds(12))
                    .until(() -> Instant.now().isAfter(expiresAt.plusSeconds(1)));
            final var verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid()).withDCQL().encrypted().createManagementResponse();
            final var requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
            final String presentation = issued.entry().createPresentationForSdJwtIndex(0, requestObject);
            final int callbacksBefore = awaitStableVerifierCallbacks();
            final var rejection = assertThrows(org.springframework.web.client.HttpClientErrorException.class,
                    () -> wallet.respondToVerification(requestObject, presentation));

            // Then
            ApiErrorAssert.assertThat(rejection)
                    .hasStatus(400)
                    .hasError("invalid_transaction_data")
                    .hasErrorCode("unresolvable_status_list");
            final var failed = verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
            assertThat(failed.getWalletResponse().getCredentialSubjectData())
                    .isNullOrEmpty();
            assertThat(statusRequests(statusRequest))
                    .isEqualTo(requestsAfterWarmup + 1);
            assertThat(verifierManager.getVerificationById(first.getId()))
                    .usingRecursiveComparison()
                    .isEqualTo(first);
            awaitOneVerifierCallback(callbacksBefore);
            assertThat(awaitStableVerifierCallbacks())
                    .isEqualTo(callbacksBefore + 1);
        } finally {
            mockServerClient.clear(expectationId);
        }
    }

    private IssuedCredential issueCredentialOnFreshList() {
        final var list = issuerManager.getStatusListApi().createStatusList(new StatusListCreate()
                .maxLength(100000).config(new StatusListCreateConfig().bits(2)));
        final var offer = issuerManager.createCredential(new CreateCredentialOfferRequest()
                .metadataCredentialSupportedId(List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT))
                .credentialSubjectData(CredentialSubjectFixtures.completeEmployeeProfile())
                .credentialMetadata(new CredentialOfferMetadataDto().deferred(false))
                .offerValiditySeconds(600).statusLists(List.of(list.getStatusRegistryUrl())));
        return new IssuedCredential(offer.getManagementId(), wallet.collectOffer(toUri(offer.getOfferDeeplink()), 1),
                list.getStatusRegistryUrl());
    }

    private ManagementResponse present(final WalletBatchEntry entry) {
        final var verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid()).withDCQL().encrypted().createManagementResponse();
        final var requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        wallet.respondToVerification(requestObject, entry.createPresentationForSdJwtIndex(0, requestObject));
        return verifierManager.getVerificationById(verification.getId());
    }

    private HttpRequest statusRequest(final String uri) {
        return request().withMethod("GET").withPath(Pattern.quote(URI.create(uri).getPath()));
    }

    private int statusRequests(final HttpRequest statusRequest) {
        return mockServerClient.retrieveRecordedRequests(statusRequest).length;
    }

    private record IssuedCredential(UUID managementId, WalletBatchEntry entry, String statusListUri) {
    }
}
