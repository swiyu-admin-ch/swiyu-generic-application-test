package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.UseWallet;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.HttpClientErrorException;

import java.util.HashMap;
import java.util.List;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@UseIssuers(IssuerVariant.COMPLETE)
@UseWallet(dpop = true, encryption = true, signedMetadata = true)
class DeferredTransactionIsolationE2ETest extends BaseTest {

    @Test
    @XrayTest(key = "EIDOMNI-1568",
            summary = "Credential Issuer rejects another offer's deferred transaction without consuming either offer",
            description = """
                    Given two READY deferred offers with distinct access tokens, transaction identifiers and Wallet keys.
                    When Wallet A sends offer B's transaction_id with A's access token and a fresh valid DPoP proof.
                    Then the Issuer returns invalid_transaction_id, leaves both offers unchanged without callbacks,
                    and subsequently issues each Credential batch only to its authorized Wallet with the expected claims.
                    Deviation: Wallet A substitutes another offer's transaction identifier while preserving its own authorization.
                    Spec: OID4VCI 1.0 §9 Deferred Credential Endpoint and §9.3 Deferred Credential Error Response;
                    Swiss issuance profile §9 requires DPoP.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCI_I1B_CREATE_DEFERRED_VERIFIABLE_CREDENTIALS)
    void deferredCredential_whenTransactionBelongsToAnotherOffer_thenRejectedWithoutConsumingEitherOffer() {
        // Given
        final var claimsA = new HashMap<>(CredentialSubjectFixtures.completeEmployeeProfile());
        claimsA.put("name", "Deferred Holder A");
        final var claimsB = new HashMap<>(CredentialSubjectFixtures.completeEmployeeProfile());
        claimsB.put("name", "Deferred Holder B");
        final var offerA = issuerManager.createDeferredCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT, claimsA);
        final var offerB = issuerManager.createDeferredCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT, claimsB);
        final var walletB = newWallet();
        final var entryA = wallet.collectTransactionIdFromDeferredOffer(toUri(offerA.getOfferDeeplink()));
        final var entryB = walletB.collectTransactionIdFromDeferredOffer(toUri(offerB.getOfferDeeplink()));
        issuerManager.updateState(offerA.getManagementId(), UpdateCredentialStatusRequestType.READY);
        issuerManager.updateState(offerB.getManagementId(), UpdateCredentialStatusRequestType.READY);
        final var transactionA = entryA.getTransactionId();
        final var transactionB = entryB.getTransactionId();
        assertThat(transactionA)
                .isNotNull()
                .isNotEqualTo(transactionB);
        assertThat(entryA.getToken().getAccessToken())
                .isNotEqualTo(entryB.getToken().getAccessToken());
        final var beforeA = issuerManager.getCredentialById(offerA.getManagementId());
        final var beforeB = issuerManager.getCredentialById(offerB.getManagementId());
        final int callbacksBefore = awaitStableIssuerCallbacks();

        // When
        entryA.setTransactionId(transactionB);
        final var rejection = assertThrows(HttpClientErrorException.class,
                () -> wallet.getCredentialFromTransactionId(entryA));

        // Then
        ApiErrorAssert.assertThat(rejection)
                .hasStatus(400)
                .hasError("invalid_transaction_id");
        assertThat(issuerManager.getCredentialById(offerA.getManagementId()))
                .usingRecursiveComparison()
                .isEqualTo(beforeA);
        assertThat(issuerManager.getCredentialById(offerB.getManagementId()))
                .usingRecursiveComparison()
                .isEqualTo(beforeB);
        assertThat(entryA.getIssuedCredentials())
                .isEmpty();
        assertThat(entryB.getIssuedCredentials())
                .isEmpty();
        assertThat(awaitStableIssuerCallbacks())
                .isEqualTo(callbacksBefore);

        // When
        entryA.setTransactionId(transactionA);
        final var responseA = wallet.getCredentialFromTransactionId(entryA);
        final var responseB = walletB.getCredentialFromTransactionId(entryB);

        // Then
        assertThat(responseA.getStatus())
                .isEqualTo(200);
        assertThat(responseB.getStatus())
                .isEqualTo(200);
        SdJwtBatchAssert.assertThat(entryA.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(claimsA);
        SdJwtBatchAssert.assertThat(entryB.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(claimsB);
        issuerManager.verifyStatus(offerA.getManagementId(), CredentialStatusType.ISSUED);
        issuerManager.verifyStatus(offerB.getManagementId(), CredentialStatusType.ISSUED);
    }

    @Test
    @XrayTest(key = "EIDOMNI-1569",
            summary = "Credential Issuer rejects a consumed deferred transaction without changing the issued result",
            description = """
                    Given a deferred offer collected successfully with a still-valid access token.
                    When the Wallet repeats the deferred collection with the consumed transaction_id and a fresh DPoP proof.
                    Then the Issuer returns invalid_transaction_id, issues no additional Credentials,
                    preserves the issued offer and produces no additional business callback.
                    Deviation: the Wallet reuses a transaction identifier after successful collection.
                    Spec: OID4VCI 1.0 §9.1 Deferred Credential Request and §9.3 Deferred Credential Error Response;
                    Swiss issuance profile §9 requires DPoP. Terminal-state immutability is a project invariant.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCI_I1B_CREATE_DEFERRED_VERIFIABLE_CREDENTIALS)
    void deferredCredential_whenConsumedTransactionIsReplayed_thenIssuedResultAndCallbacksStayUnchanged() {
        // Given
        final var offer = issuerManager.createDeferredCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final var entry = wallet.collectTransactionIdFromDeferredOffer(toUri(offer.getOfferDeeplink()));
        final var consumedTransaction = entry.getTransactionId();
        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.READY);
        final var response = wallet.getCredentialFromTransactionId(entry);
        assertThat(response.getStatus())
                .isEqualTo(200);
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.ISSUED);
        final var issued = issuerManager.getCredentialById(offer.getManagementId());
        final var credentials = List.copyOf(entry.getIssuedCredentials());
        final int callbacksBefore = awaitStableIssuerCallbacks();

        // When
        entry.setTransactionId(consumedTransaction);
        final var rejection = assertThrows(HttpClientErrorException.class,
                () -> wallet.getCredentialFromTransactionId(entry));

        // Then
        ApiErrorAssert.assertThat(rejection)
                .hasStatus(400)
                .hasError("invalid_transaction_id");
        assertThat(issuerManager.getCredentialById(offer.getManagementId()))
                .usingRecursiveComparison()
                .isEqualTo(issued);
        assertThat(entry.getIssuedCredentials())
                .containsExactlyElementsOf(credentials);
        assertThat(awaitStableIssuerCallbacks())
                .isEqualTo(callbacksBefore);
    }
}
