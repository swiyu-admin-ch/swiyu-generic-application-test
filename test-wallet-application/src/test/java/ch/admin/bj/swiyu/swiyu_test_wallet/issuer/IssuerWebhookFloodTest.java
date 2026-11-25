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
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.time.Duration;
import java.util.List;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

/**
 * Rejected key proofs leave the offer available for issuance with a valid proof and a single ISSUED callback.
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
            key = "EIDOMNI-1409",
            summary = "Credential Issuer issues a credential after repeated invalid key proofs are rejected",
            description = """
                    Given a bound Credential Offer and its access token.
                    When the Wallet sends six requests with the same invalid jwt key proof, then a valid proof using that access token.
                    Then all invalid requests return HTTP 400 invalid_proof, one Credential is issued, the offer becomes ISSUED and its status callback is delivered once.
                    Deviation: the rejected key proof aud differs from the Credential Issuer Identifier.
                    Spec: OID4VCI 1.0 §8.3 Credential Response, §8.3.1 Credential Error Response and Appendix F.1 jwt Proof Type;
                    Swiss issuance profile §8.3 Credential Response. Recovery and callbacks are ticket regression invariants.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCI_I1_ISSUING_VERIFIABLE_CREDENTIALS)
    @Tag(ReportingTags.UCI_I1A_CREATE_VERIFIABLE_CREDENTIALS)
    @Tag(ReportingTags.UCI_I1D_CREATE_WEBHOOK_STATUS_CHANGE)
    void credentialRequest_whenWalletUsesValidProofAfterRepeatedInvalidProof_thenIssuanceStillSucceeds() {
        // Given
        final var offer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final WalletBatchEntry entry = wallet.receiveOfferAndCollectToken(toUri(offer.getOfferDeeplink()), 1);
        final var offerBefore = issuerManager.getCredentialOfferById(offer.getManagementId(), offer.getOfferId());
        entry.setProofsFromJwt(List.of(frozenProofForAnotherIssuer(entry)));
        for (int request = 0; request < REPEATED_REQUESTS; request++) {
            final var rejection = assertThrows(HttpClientErrorException.class, () -> wallet.postCredentialRequest(entry));
            ApiErrorAssert.assertThat(rejection)
                    .hasStatus(400)
                    .hasError("invalid_proof");
        }
        assertThat(entry.getIssuedCredentials())
                .isEmpty();
        assertThat(issuerManager.getCredentialOfferById(offer.getManagementId(), offer.getOfferId()))
                .usingRecursiveComparison()
                .isEqualTo(offerBefore);

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

    /** Reuse the same serialized key proof for every rejected request. */
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
}
