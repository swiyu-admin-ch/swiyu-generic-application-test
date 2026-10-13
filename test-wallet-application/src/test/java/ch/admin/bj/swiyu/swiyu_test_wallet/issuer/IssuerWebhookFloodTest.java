package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.WebhookCallback;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.JwtProof;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.UseWallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockserver.matchers.MatchType;
import org.mockserver.matchers.TimeToLive;
import org.mockserver.matchers.Times;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.sql.SQLException;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.mock.MockServices.ISSUER_CALLBACK_PATH;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.mockserver.model.JsonBody.json;

/**
 * A malicious Wallet repeats a rejected key proof using its access token. The callback queue must stay bounded while
 * the Business Issuer is unavailable, and rejecting the proof must leave issuance recoverable.
 * The callback bound is a ticket requirement; OID4VCI does not define business webhooks.
 */
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.COMPLETE)
@UseWallet(dpop = true, encryption = true, signedMetadata = true)
class IssuerWebhookFloodTest extends BaseTest {

    private static final int REPEATED_REQUESTS = 6;
    private static final Duration CALLBACK_OBSERVATION = Duration.ofSeconds(1);
    private static final Duration CALLBACK_TIMEOUT = Duration.ofSeconds(5);

    @Test
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Credential Issuer bounds queued error callbacks for a repeated invalid key proof",
            description = """
                    Given a bound Credential Offer, an access token and a Business Issuer answering error callbacks with HTTP 503.
                    When the Wallet sends six Credential Requests with the same serialized invalid jwt key proof and fresh DPoP proofs.
                    Then each request returns HTTP 400 invalid_proof, the offer remains unchanged and exactly one KEY_BINDING_ERROR event stays queued.
                    Deviation: the key proof aud differs from the Credential Issuer Identifier; the Business Issuer is unavailable.
                    Spec: OID4VCI 1.0 §8.3.1 Credential Error Response and Appendix F.1 jwt Proof Type;
                    Swiss issuance profile §8.2 Credential Request. The callback bound comes from the ticket.
                    """)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    void credentialRequest_whenWalletRepeatsInvalidProofAndCallbackIsUnavailable_thenQueueStaysBounded() {
        // Given: freeze the proof, while the Wallet still creates fresh DPoP and encrypted request envelopes.
        final var offer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final WalletBatchEntry entry = wallet.receiveOfferAndCollectToken(toUri(offer.getOfferDeeplink()), 1);
        final var offerBefore = issuerManager.getCredentialOfferById(offer.getManagementId(), offer.getOfferId());
        entry.setProofsFromJwt(List.of(frozenProofForAnotherIssuer(entry)));
        final var errorCallback = request()
                .withMethod("POST")
                .withPath(ISSUER_CALLBACK_PATH)
                .withBody(json("""
                        {"subject_id":"%s","event":"KEY_BINDING_ERROR"}
                        """.formatted(offer.getOfferId()), MatchType.ONLY_MATCHING_FIELDS));
        final var expectations = mockServerClient
                .when(errorCallback, Times.unlimited(), TimeToLive.unlimited(), 100)
                .respond(response().withStatusCode(503));

        try {
            // When: the first error must actually be queued and its delivery must fail before further requests.
            final var firstRejection = assertThrows(HttpClientErrorException.class, () -> wallet.postCredentialRequest(entry));
            ApiErrorAssert.assertThat(firstRejection)
                    .hasStatus(400)
                    .hasError("invalid_proof");
            await()
                    .atMost(CALLBACK_TIMEOUT)
                    .untilAsserted(() -> {
                        assertThat(queuedKeyBindingErrors(offer.getOfferId()))
                                .isEqualTo(1);
                        assertThat(mockServerClient.retrieveRecordedRequests(errorCallback))
                                .isNotEmpty();
                    });
            for (int request = 1; request < REPEATED_REQUESTS; request++) {
                final var rejection = assertThrows(HttpClientErrorException.class, () -> wallet.postCredentialRequest(entry));
                ApiErrorAssert.assertThat(rejection)
                        .hasStatus(400)
                        .hasError("invalid_proof");
            }

            // Then: a delivery retry does not count as another queued event.
            assertThat(entry.getIssuedCredentials())
                    .isEmpty();
            assertThat(issuerManager.getCredentialOfferById(offer.getManagementId(), offer.getOfferId()))
                    .usingRecursiveComparison()
                    .isEqualTo(offerBefore);
            await()
                    .during(CALLBACK_OBSERVATION)
                    .atMost(CALLBACK_TIMEOUT)
                    .untilAsserted(() -> assertThat(queuedKeyBindingErrors(offer.getOfferId()))
                            .as("Queued KEY_BINDING_ERROR events after %d requests", REPEATED_REQUESTS)
                            .isEqualTo(1));
        } finally {
            mockServerClient.clear(expectations[0].getId());
            // Restore delivery and drain only this offer's events, including when a product defect fails the assertion.
            await()
                    .atMost(CALLBACK_TIMEOUT)
                    .until(() -> queuedKeyBindingErrors(offer.getOfferId()) == 0);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Credential Issuer issues a credential after repeated invalid key proofs are rejected",
            description = """
                    Given a bound Credential Offer and its access token.
                    When the Wallet sends six requests with the same invalid jwt key proof, then a valid proof using that access token.
                    Then all invalid requests return HTTP 400 invalid_proof, one Credential is issued, the offer becomes ISSUED and its status callback is delivered once.
                    Deviation: the rejected key proof aud differs from the Credential Issuer Identifier.
                    Spec: OID4VCI 1.0 §8.3 Credential Response, §8.3.1 Credential Error Response and Appendix F.1 jwt Proof Type;
                    Swiss issuance profile §8.3 Credential Response. Recovery and callbacks are ticket regression invariants.
                    """)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    void credentialRequest_whenWalletUsesValidProofAfterRepeatedInvalidProof_thenIssuanceStillSucceeds() {
        // Given
        final var offer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final WalletBatchEntry entry = wallet.receiveOfferAndCollectToken(toUri(offer.getOfferDeeplink()), 1);
        entry.setProofsFromJwt(List.of(frozenProofForAnotherIssuer(entry)));
        for (int request = 0; request < REPEATED_REQUESTS; request++) {
            final var rejection = assertThrows(HttpClientErrorException.class, () -> wallet.postCredentialRequest(entry));
            ApiErrorAssert.assertThat(rejection)
                    .hasStatus(400)
                    .hasError("invalid_proof");
        }
        assertThat(entry.getIssuedCredentials())
                .isEmpty();

        // When
        entry.createProofs(wallet.collectCNonce(entry));
        wallet.postCredentialRequest(entry);

        // Then
        assertThat(entry.getIssuedCredentials())
                .hasSize(1);
        assertThat(issuerManager.getCredentialOfferById(offer.getManagementId(), offer.getOfferId()).getStatus())
                .isEqualTo(CredentialStatusType.ISSUED);
        await()
                .during(CALLBACK_OBSERVATION)
                .atMost(CALLBACK_TIMEOUT)
                .untilAsserted(() -> assertThat(issuerCallbacks().stream()
                        .filter(callback -> offer.getOfferId().equals(callback.getSubjectId()))
                        .filter(callback -> callback.getEventType() == WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                        .filter(callback -> "ISSUED".equals(callback.getEvent()))
                        .toList())
                        .hasSize(1));
    }

    /** Keep the serialized proof identical; a new signature on every repeat could mask request deduplication bugs. */
    private JwtProof frozenProofForAnotherIssuer(final WalletBatchEntry entry) {
        final JwtProof proof = new JwtProof(
                "https://another-credential-issuer.example",
                wallet.collectCNonce(entry),
                entry.getHolderPublicKeys().getFirst(),
                entry.getHolderKeyPairs().getFirst(),
                null);
        final String serializedProof = proof.toJwt();
        final JwtProof frozenProof = spy(proof);
        doReturn(serializedProof).when(frozenProof).toJwt();
        return frozenProof;
    }

    private long queuedKeyBindingErrors(final UUID offerId) throws SQLException {
        final String sql = "SELECT count(*) FROM %s.callback_event WHERE subject_id = ? AND type = 'ERROR' AND event = 'KEY_BINDING_ERROR'"
                .formatted(issuerImageConfig.getDbSchema());
        try (var query = connection.prepareStatement(sql)) {
            query.setObject(1, offerId);
            try (var result = query.executeQuery()) {
                result.next();
                return result.getLong(1);
            }
        }
    }
}
