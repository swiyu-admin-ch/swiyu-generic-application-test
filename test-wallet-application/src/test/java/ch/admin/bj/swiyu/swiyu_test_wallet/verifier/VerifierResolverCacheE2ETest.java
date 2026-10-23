package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.TrustMethod;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ContainerLogConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseVerifiers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.identity.KeyUtil;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.mock.tp2.Tp2TrustStatementRouteSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.jwk.JWK;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockserver.matchers.TimeToLive;
import org.mockserver.matchers.Times;
import org.mockserver.model.HttpRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.HttpStatusCodeException;
import org.testcontainers.containers.GenericContainer;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static ch.admin.bj.swiyu.swiyu_test_wallet.mock.tp2.Tp2TrustStatementRouteSupport.identityTrustStatementPathRequest;
import static ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result.VerificationFailureAssert.assertRejected;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.DEFAULT_CREDENTIAL_ID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.CACHED)
@UseVerifiers(VerifierVariant.CACHED)
class VerifierResolverCacheE2ETest extends BaseTest {

    private static final Duration VERIFIER_RESOLVER_CACHE_WAIT = Duration.ofSeconds(10);
    private static final Duration TP2_TRUST_STATEMENT_CACHE_TTL = Duration.ofSeconds(5);

    @Autowired
    private ContainerLogConfig containerLogConfig;

    @Test
    @XrayTest(
            key = "EIDOMNI-1157",
            summary = "Verifier JWK cache expires and rejects a tampered issuer DID log",
            description = """
                    Given the verifier cached profile with a short JWK cache TTL.
                    And an issuer credential signed with the original issuer assertion key.
                    When the assertion key in the served issuer DID log is replaced without a valid integrity proof.
                    And the cache eviction interval has elapsed.
                    When the same credential is presented again.
                    Then the verifier re-resolves and rejects the tampered issuer DID log.
                    """)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This fix is not available yet"
    )
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCV_O2_SUBMIT_VERIFICATION_PRESENTATION)
    @Tag(ReportingTags.UCV_O2A_VERIFY_PRESENTATION_SUBMISSION_AND_SD_JWT_CREDENTIAL)
    void verification_whenJwkCacheTtlExpires_thenTamperedIssuerDidLogIsResolvedAndCredentialRejected() {
        // Given
        awaitResolverCacheTtlBoundary();
        final WalletBatchEntry batchEntry = issueBoundCredential();
        final int didRequestsBefore = issuerDidDocumentRequests();

        try {
            // When
            final ManagementResponse successfulVerification = verifyCredentialWithAcceptedIssuer(batchEntry);

            // Then
            final int didRequestsAfterFirstVerification = issuerDidDocumentRequests();
            assertThat(didRequestsAfterFirstVerification)
                    .as("First verification should resolve the issuer DID document")
                    .isGreaterThan(didRequestsBefore);

            // When
            mockServices.replaceDidLog(issuerConfig.getIssuerDid(), didLogWithTamperedAssertionKey());
            awaitResolverCacheTtlBoundary();
            final RejectedVerification rejectedVerification = presentCredentialWithAcceptedIssuerExpectingHttpError(
                    batchEntry
            );

            // Then
            assertThat(rejectedVerification.exception().getStatusCode().value())
                    .as("Tampered issuer DID log rejection HTTP status")
                    .isIn(400, 500);
            verifierManager.verifyState(
                    successfulVerification.getId(),
                    VerificationStatus.SUCCESS,
                    "The successful verification must remain in its terminal state"
            );
            verifierManager.verifyHasNotState(
                    rejectedVerification.verificationId(),
                    VerificationStatus.SUCCESS,
                    "The rejected verification must not reach the SUCCESS terminal state"
            );
            assertThat(issuerDidDocumentRequests())
                    .as("Issuer DID document should be resolved again after JWK_CACHE TTL expiry")
                    .isGreaterThan(didRequestsAfterFirstVerification);
        } finally {
            mockServices.replaceDidLog(issuerConfig.getIssuerDid(), issuerConfig.getIssuerDidLog());
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1158",
            summary = "Verifier trust statement cache expires and re-queries trust registry",
            description = """
                    Given the verifier cached profile with a short trust statement cache TTL.
                    And a trust registry that returns a valid issuance trust statement once, then no trust statements.
                    When the cache eviction interval has elapsed and another verification is performed.
                    Then the verifier re-queries the trust registry and rejects the now-untrusted issuer.
                    """)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This fix is not available yet"
    )
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCV_M3_RETRIEVE_VERIFICATION_RESULT)
    @Tag(ReportingTags.UCV_O2_SUBMIT_VERIFICATION_PRESENTATION)
    @Tag(ReportingTags.UCV_O2A_VERIFY_PRESENTATION_SUBMISSION_AND_SD_JWT_CREDENTIAL)
    @Tag(ReportingTags.UCV_O2F_VALIDATE_ISSUER_VIA_TRUST_REGISTRY_TP2_VERIFIER_VIEW)
    void verification_whenTrustStatementCacheTtlExpires_thenTrustRegistryIsQueriedAgain() {
        // Given
        final WalletBatchEntry batchEntry = issueBoundCredential();
        final IdentityTrustRoute trustRoute = registerTp2TrustRouteThatStopsTrustingIssuerAfterFirstFetch();
        final int trustRequestsBefore = trustStatementRequests(trustRoute);

        try (final GenericContainer<?> trustedVerifierContainer = createVerifierWithCachedTp2Trust()) {
            trustedVerifierContainer.start();
            final BusinessVerifier trustedVerifier = new BusinessVerifier("http://%s:%d".formatted(
                    trustedVerifierContainer.getHost(), trustedVerifierContainer.getMappedPort(8080)));
            wallet.useVerifier(new ServiceLocationContext(
                    trustedVerifierContainer.getHost(), trustedVerifierContainer.getMappedPort(8080).toString()));
            wallet.setUseEncryption(true);

            // When: the first verification loads a valid issuer idTS into the TP2 cache.
            final ManagementResponse firstVerification = presentCredentialWithTp2Trust(batchEntry, trustedVerifier);

            // Then
            assertThat(firstVerification.getState())
                    .isEqualTo(VerificationStatus.SUCCESS);
            assertThat(firstVerification.getCredentialEvaluation().get(DEFAULT_CREDENTIAL_ID))
                    .singleElement()
                    .satisfies(evaluation -> {
                        assertThat(evaluation.getTrustMarkers())
                                .isNotNull();
                        assertThat(evaluation.getTrustMarkers().getIsTrusted())
                                .isTrue();
                        assertThat(evaluation.getTrustMarkers().getTrustMethod())
                                .isEqualTo(TrustMethod.TRUST_PROTOCOL_2_0);
                    });
            final int trustRequestsAfterFirstVerification = trustStatementRequests(trustRoute);
            assertThat(trustRequestsAfterFirstVerification)
                    .as("First verification should fetch the issuer idTS from the TP2 registry")
                    .isEqualTo(trustRequestsBefore + 1);

            // When: the registry no longer serves the idTS, but the cache entry is still valid.
            final ManagementResponse cachedVerification = presentCredentialWithTp2Trust(batchEntry, trustedVerifier);

            // Then
            assertThat(cachedVerification.getState())
                    .isEqualTo(VerificationStatus.SUCCESS);
            assertThat(trustStatementRequests(trustRoute))
                    .as("A verification within the TP2 cache TTL must reuse the cached issuer idTS")
                    .isEqualTo(trustRequestsAfterFirstVerification);

            // When: the cache TTL expires while the original idTS itself is still valid.
            awaitResolverCacheTtlBoundary();
            final ManagementResponse verification = trustedVerifier.verificationRequest()
                    .withDCQL()
                    .encrypted()
                    .createManagementResponse();
            final RequestObject requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
            final String presentation = batchEntry.createPresentationForSdJwtIndex(0, requestObject);

            // Then
            assertRejected(
                    () -> wallet.respondToVerification(requestObject, presentation),
                    trustedVerifier,
                    verification.getId(),
                    exception -> ApiErrorAssert.assertThat(exception)
                            .hasStatus(400)
                            .hasError("invalid_transaction_data"),
                    evaluation -> {
                        assertThat(evaluation.getTrustMarkers())
                                .isNotNull();
                        assertThat(evaluation.getTrustMarkers().getIsTrusted())
                                .isFalse();
                        assertThat(evaluation.getTrustMarkers().getTrustMethod())
                                .isEqualTo(TrustMethod.TRUST_PROTOCOL_2_0);
                    }
            );
            assertThat(trustStatementRequests(trustRoute))
                    .as("TP2 registry should be queried again after the issuer idTS cache TTL expires")
                    .isEqualTo(trustRequestsAfterFirstVerification + 1);
            assertThat(trustedVerifier.getVerificationById(firstVerification.getId()))
                    .usingRecursiveComparison()
                    .isEqualTo(firstVerification);
        } finally {
            mockServerClient.clear(trustRoute.expectationId());
            wallet.useVerifier(currentVerifier);
        }
    }

    private WalletBatchEntry issueBoundCredential() {
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
        );
        return wallet.collectOffer(toUri(response.getOfferDeeplink()));
    }

    private ManagementResponse verifyCredentialWithAcceptedIssuer(final WalletBatchEntry batchEntry) {
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withDCQL()
                .createManagementResponse();
        final RequestObject requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = batchEntry.createPresentationForSdJwtIndex(0, requestObject);

        wallet.respondToVerification(requestObject, presentation);

        return verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
    }

    private RejectedVerification presentCredentialWithAcceptedIssuerExpectingHttpError(
            final WalletBatchEntry batchEntry
    ) {
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withDCQL()
                .createManagementResponse();
        final RequestObject requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = batchEntry.createPresentationForSdJwtIndex(0, requestObject);

        final HttpStatusCodeException ex = assertThrows(
                HttpStatusCodeException.class,
                () -> wallet.respondToVerification(requestObject, presentation)
        );
        return new RejectedVerification(ex, verification.getId());
    }

    private ManagementResponse presentCredentialWithTp2Trust(
            final WalletBatchEntry batchEntry,
            final BusinessVerifier trustedVerifier
    ) {
        final ManagementResponse verification = trustedVerifier.verificationRequest()
                .withDCQL()
                .encrypted()
                .createManagementResponse();
        final RequestObject requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = batchEntry.createPresentationForSdJwtIndex(0, requestObject);

        wallet.respondToVerification(requestObject, presentation);

        return trustedVerifier.getVerificationById(verification.getId());
    }

    private IdentityTrustRoute registerTp2TrustRouteThatStopsTrustingIssuerAfterFirstFetch() {
        // Reuse the valid, long-lived idTS from the TP2 fixture before overriding only this issuer's route.
        final String trustedResponse = restClient.get()
                .uri("http://%s:%d%s/{did}".formatted(
                        mockServerContainer.getHost(),
                        mockServerContainer.getServerPort(),
                        Tp2TrustStatementRouteSupport.IDENTITY_TRUST_STATEMENT_PATH), issuerConfig.getIssuerDid())
                .retrieve()
                .body(String.class);
        final HttpRequest issuerIdTsRequest = identityTrustStatementPathRequest(issuerConfig.getIssuerDid());
        final AtomicInteger registryFetches = new AtomicInteger();

        final var expectations = mockServerClient.when(
                        issuerIdTsRequest,
                        Times.unlimited(),
                        TimeToLive.unlimited(),
                        300
                )
                .respond(httpRequest -> registryFetches.getAndIncrement() == 0
                        ? response()
                                .withStatusCode(200)
                                .withHeader(HttpHeaders.CONTENT_TYPE, "application/jwt")
                                .withBody(trustedResponse)
                        : response()
                                .withStatusCode(404));

        return new IdentityTrustRoute(issuerIdTsRequest, expectations[0].getId());
    }

    private GenericContainer<?> createVerifierWithCachedTp2Trust() {
        final var imageConfig = VerifierVariant.CACHED.imageConfig(verifierImageConfig);
        imageConfig.setSurname("trust_cache_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16));
        imageConfig.setTrustRegistryMaxCacheTtlSeconds(TP2_TRUST_STATEMENT_CACHE_TTL.toSeconds());
        return VerifierContainerConfig.createVerifierContainer(
                verifierContainer.getNetwork(),
                dbTestContainer,
                verifierConfig,
                verifierContainer.getDockerImageName(),
                imageConfig,
                managementAuthConfig,
                null,
                containerLogConfig
        ).withEnv("SWIYU_TRUST_ISSUER_DID", trustConfig.getTrustDid());
    }

    private int issuerDidDocumentRequests() {
        return mockServerClient.retrieveRecordedRequests(
                request()
                        .withMethod("GET")
                        .withPath("/api/v1/did/" + didIdentifier(issuerConfig.getIssuerDid()) + "/did.jsonl")
        ).length;
    }

    private int trustStatementRequests(final IdentityTrustRoute trustRoute) {
        return mockServerClient.retrieveRecordedRequests(trustRoute.request()).length;
    }

    private String didIdentifier(final String did) {
        return did.substring(did.lastIndexOf(':') + 1);
    }

    private String didLogWithTamperedAssertionKey() {
        final JsonObject didLog = JsonParser.parseString(issuerConfig.getIssuerDidLog()).getAsJsonObject();
        final JsonObject didDocument = didLog.getAsJsonObject("state");
        final JsonArray verificationMethods = didDocument.getAsJsonArray("verificationMethod");
        final JWK tamperedAssertionKey = KeyUtil.createJWKFromKeyPair(KeyUtil.generateEC256KeyPair()).toPublicJWK();

        for (int i = 0; i < verificationMethods.size(); i++) {
            final JsonObject verificationMethod = verificationMethods.get(i).getAsJsonObject();
            if (issuerConfig.getIssuerAssertKeyId().equals(verificationMethod.get("id").getAsString())) {
                final JsonObject currentPublicJwk = verificationMethod.getAsJsonObject("publicKeyJwk");
                final JsonObject tamperedPublicJwk = JsonParser.parseString(tamperedAssertionKey.toJSONString())
                        .getAsJsonObject();
                if (currentPublicJwk.has("kid")) {
                    tamperedPublicJwk.add("kid", currentPublicJwk.get("kid"));
                }
                verificationMethod.add("publicKeyJwk", tamperedPublicJwk);
                return didLog.toString();
            }
        }

        throw new IllegalStateException("Issuer assertion key not found in DID log");
    }

    private void awaitResolverCacheTtlBoundary() {
        final Instant cacheBoundary = Instant.now().plus(VERIFIER_RESOLVER_CACHE_WAIT);

        await()
                .pollInterval(Duration.ofMillis(100))
                .atMost(VERIFIER_RESOLVER_CACHE_WAIT.plusSeconds(1))
                .until(() -> Instant.now().isAfter(cacheBoundary));
    }

    private record IdentityTrustRoute(HttpRequest request, String expectationId) {
    }

    private record RejectedVerification(HttpStatusCodeException exception, UUID verificationId) {
    }
}
