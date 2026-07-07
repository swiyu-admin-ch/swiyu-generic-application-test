package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.TrustAnchor;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseVerifiers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.jwk.JWK;
import org.apache.http.protocol.HTTP;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockserver.matchers.TimeToLive;
import org.mockserver.matchers.Times;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.DEFAULT_VCT;
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

    private static final Duration VERIFIER_RESOLVER_CACHE_TTL = Duration.ofSeconds(2);
    private static final Duration VERIFIER_RESOLVER_CACHE_EVICTION_CUSHION = Duration.ofSeconds(2);

    @Test
    @XrayTest(
            key = "EIDOMNI-1157",
            summary = "Verifier JWK cache expires and rejects credentials signed with a rotated issuer key",
            description = """
                    Given the verifier cached profile with a short JWK cache TTL.
                    And an issuer credential signed with the original issuer assertion key.
                    When the issuer DID document rotates the assertion key after the verifier populated JWK_CACHE.
                    Then the same credential is still accepted before TTL expiry because the verifier uses JWK_CACHE.
                    When the TTL expires and the same credential is presented again.
                    Then the verifier re-resolves the issuer DID document and rejects the credential signed with the old key.
                    """)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This fix is not available yet"
    )
    @Tag(ReportingTags.EDGE_CASE)
    void verification_whenJwkCacheTtlExpires_thenRotatedIssuerDidKeyIsResolvedAndCredentialRejected() {
        // Given
        awaitResolverCacheTtlBoundary();
        final WalletBatchEntry batchEntry = issueBoundCredential();
        final int didRequestsBefore = issuerDidDocumentRequests();

        try {
            // When
            verifyCredentialWithAcceptedIssuer(batchEntry);

            // Then
            final int didRequestsAfterFirstVerification = issuerDidDocumentRequests();
            assertThat(didRequestsAfterFirstVerification)
                    .as("First verification should resolve the issuer DID document")
                    .isGreaterThan(didRequestsBefore);

            // When
            mockServerClientConfig.replaceDidLog(issuerConfig.getIssuerDid(), didLogWithRotatedAssertionKey());
            verifyCredentialWithAcceptedIssuer(batchEntry);

            // Then
            assertThat(issuerDidDocumentRequests())
                    .as("Issuer DID document should be served from JWK_CACHE before TTL expiry")
                    .isEqualTo(didRequestsAfterFirstVerification);

            // When
            awaitResolverCacheTtlBoundary();
            final HttpClientErrorException ex = assertCredentialRejectedWithAcceptedIssuer(batchEntry);

            // Then
            ApiErrorAssert.assertThat(ex).hasStatus(400);
            assertThat(issuerDidDocumentRequests())
                    .as("Issuer DID document should be resolved again after JWK_CACHE TTL expiry")
                    .isGreaterThan(didRequestsAfterFirstVerification);
        } finally {
            mockServerClientConfig.replaceDidLog(issuerConfig.getIssuerDid(), issuerConfig.getIssuerDidLog());
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1158",
            summary = "Verifier trust statement cache expires and re-queries trust registry",
            description = """
                    Given the verifier cached profile with a short trust statement cache TTL.
                    And a trust registry that returns a valid issuance trust statement once, then no trust statements.
                    When the same issuer credential is verified twice within the TTL.
                    Then the second verification still uses the cached trust statement.
                    When the TTL expires and another verification is performed.
                    Then the verifier re-queries the trust registry and rejects the now-untrusted issuer.
                    """)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This fix is not available yet"
    )
    @Tag(ReportingTags.EDGE_CASE)
    void verification_whenTrustStatementCacheTtlExpires_thenTrustRegistryIsQueriedAgain() {
        // Given
        final WalletBatchEntry batchEntry = issueBoundCredential();
        final LegacyTrustRoute trustRoute = registerLegacyTrustRouteThatStopsTrustingIssuerAfterFirstFetch();
        final TrustAnchor trustAnchor = new TrustAnchor()
                .did(trustConfig.getTrustDid())
                .trustRegistryUri(trustRoute.trustRegistryUri());
        final int trustRequestsBefore = trustStatementRequests(trustRoute);

        // When
        verifyCredentialWithTrustAnchor(batchEntry, trustAnchor);

        // Then
        final int trustRequestsAfterFirstVerification = trustStatementRequests(trustRoute);
        assertThat(trustRequestsAfterFirstVerification)
                .as("First verification should fetch the trust statement from the registry")
                .isEqualTo(trustRequestsBefore + 1);

        // When
        verifyCredentialWithTrustAnchor(batchEntry, trustAnchor);

        // Then
        assertThat(trustStatementRequests(trustRoute))
                .as("Trust registry should not be queried again before TRUST_STATEMENT_CACHE TTL expiry")
                .isEqualTo(trustRequestsAfterFirstVerification);

        // When
        awaitResolverCacheTtlBoundary();
        final HttpClientErrorException ex = assertCredentialRejectedWithTrustAnchor(batchEntry, trustAnchor);

        // Then
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasError("invalid_transaction_data")
                .hasDetail("issuer_not_accepted")
                .hasErrorDescription("Issuer not in list of accepted issuers or connected to trust anchor");
        assertThat(trustStatementRequests(trustRoute))
                .as("Trust registry should be queried again after TRUST_STATEMENT_CACHE TTL expiry")
                .isEqualTo(trustRequestsAfterFirstVerification + 1);
    }

    private WalletBatchEntry issueBoundCredential() {
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
        );
        return wallet.collectOffer(toUri(response.getOfferDeeplink()));
    }

    private void verifyCredentialWithAcceptedIssuer(final WalletBatchEntry batchEntry) {
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withDCQL()
                .createManagementResponse();
        final RequestObject requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = batchEntry.createPresentationForSdJwtIndex(0, requestObject);

        wallet.respondToVerification(requestObject, presentation);

        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
    }

    private HttpClientErrorException assertCredentialRejectedWithAcceptedIssuer(final WalletBatchEntry batchEntry) {
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withDCQL()
                .createManagementResponse();
        final RequestObject requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = batchEntry.createPresentationForSdJwtIndex(0, requestObject);

        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.respondToVerification(requestObject, presentation)
        );
        verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
        return ex;
    }

    private void verifyCredentialWithTrustAnchor(final WalletBatchEntry batchEntry, final TrustAnchor trustAnchor) {
        final ManagementResponse verification = verifierManager.verificationRequest()
                .trustAnchor(trustAnchor)
                .withDCQL()
                .createManagementResponse();
        final RequestObject requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = batchEntry.createPresentationForSdJwtIndex(0, requestObject);

        wallet.respondToVerification(requestObject, presentation);

        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
    }

    private HttpClientErrorException assertCredentialRejectedWithTrustAnchor(final WalletBatchEntry batchEntry,
                                                                            final TrustAnchor trustAnchor) {
        final ManagementResponse verification = verifierManager.verificationRequest()
                .trustAnchor(trustAnchor)
                .withDCQL()
                .createManagementResponse();
        final RequestObject requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = batchEntry.createPresentationForSdJwtIndex(0, requestObject);

        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.respondToVerification(requestObject, presentation)
        );
        verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
        return ex;
    }

    private LegacyTrustRoute registerLegacyTrustRouteThatStopsTrustingIssuerAfterFirstFetch() {
        final String routePrefix = "/trusted-cache-" + UUID.randomUUID();
        final String routePath = routePrefix + "/api/v1/truststatements/issuance";
        final String trustedResponse = "[\"%s\"]".formatted(
                mockServerClientConfig.createLegacyIssuanceTrustStatement(DEFAULT_VCT, issuerConfig)
        );
        final AtomicInteger registryFetches = new AtomicInteger();

        mockServerClient.when(
                        request().withMethod("GET").withPath(routePath),
                        Times.unlimited(),
                        TimeToLive.unlimited(),
                        100
                )
                .respond(httpRequest -> response()
                        .withStatusCode(200)
                        .withHeader(HTTP.CONTENT_TYPE, "application/json")
                        .withBody(registryFetches.getAndIncrement() == 0
                                ? trustedResponse
                                : "[]"));

        return new LegacyTrustRoute(
                "https://%s%s".formatted(MockServerClientConfig.MOCKSERVER_HOST, routePrefix),
                routePath
        );
    }

    private int issuerDidDocumentRequests() {
        return mockServerClient.retrieveRecordedRequests(
                request()
                        .withMethod("GET")
                        .withPath("/api/v1/did/" + didIdentifier(issuerConfig.getIssuerDid()) + "/did.jsonl")
        ).length;
    }

    private int trustStatementRequests(final LegacyTrustRoute trustRoute) {
        return mockServerClient.retrieveRecordedRequests(
                request()
                        .withMethod("GET")
                        .withPath(trustRoute.routePath())
        ).length;
    }

    private String didIdentifier(final String did) {
        return did.substring(did.lastIndexOf(':') + 1);
    }

    private String didLogWithRotatedAssertionKey() {
        final JsonArray didLog = JsonParser.parseString(issuerConfig.getIssuerDidLog()).getAsJsonArray();
        final JsonObject didDocument = didLog.get(3)
                .getAsJsonObject()
                .getAsJsonObject("value");
        final JsonArray verificationMethods = didDocument.getAsJsonArray("verificationMethod");
        final JWK rotatedAssertionKey = KeyUtil.createJWKFromKeyPair(KeyUtil.generateEC256KeyPair()).toPublicJWK();

        for (int i = 0; i < verificationMethods.size(); i++) {
            final JsonObject verificationMethod = verificationMethods.get(i).getAsJsonObject();
            if (issuerConfig.getIssuerAssertKeyId().equals(verificationMethod.get("id").getAsString())) {
                final JsonObject currentPublicJwk = verificationMethod.getAsJsonObject("publicKeyJwk");
                final JsonObject rotatedPublicJwk = JsonParser.parseString(rotatedAssertionKey.toJSONString())
                        .getAsJsonObject();
                if (currentPublicJwk.has("kid")) {
                    rotatedPublicJwk.add("kid", currentPublicJwk.get("kid"));
                }
                verificationMethod.add("publicKeyJwk", rotatedPublicJwk);
                return didLog.toString();
            }
        }

        throw new IllegalStateException("Issuer assertion key not found in DID log");
    }

    private void awaitResolverCacheTtlBoundary() {
        final Instant cacheBoundary = Instant.now()
                .plus(VERIFIER_RESOLVER_CACHE_TTL)
                .plus(VERIFIER_RESOLVER_CACHE_EVICTION_CUSHION);

        await()
                .pollInterval(Duration.ofMillis(100))
                .atMost(VERIFIER_RESOLVER_CACHE_TTL
                        .plus(VERIFIER_RESOLVER_CACHE_EVICTION_CUSHION)
                        .plusSeconds(1))
                .until(() -> Instant.now().isAfter(cacheBoundary));
    }

    private record LegacyTrustRoute(String trustRegistryUri, String routePath) {
    }
}
