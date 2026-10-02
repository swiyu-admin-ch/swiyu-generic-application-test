package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.OAuthToken;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.UseWallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto.DPoPSupport;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.DEFAULT)
@UseWallet(dpop = true)
class TransactionCodeTest extends BaseTest {

    private static final String ZERO_TRANSACTION_CODE = "000000";

    @Test
    @XrayTest(
            key = "EIDOMNI-1346",
            summary = "Redeem a pre-authorized credential offer with a valid transaction code",
            description = """
                    Verifies that a transaction code explicitly enabled for the offer is returned to the Business
                    Issuer as a six-digit numeric value, advertised in the credential offer, and accepted together
                    with a DPoP-protected pre-authorized code token request.
                    """)
    @Tag(ReportingTags.UCI_C1)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.HAPPY_PATH)
    void preAuthorizedOffer_whenTransactionCodeIsValid_thenCredentialIsIssued() {
        // Given
        final CredentialWithDeeplinkResponse credentialOffer = issuerManager.createCredentialOfferWithTransactionCode(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);

        assertThat(credentialOffer.getTxCode())
                .as("transaction code returned to the Business Issuer")
                .matches("^[0-9]{6}$");

        // When
        final WalletBatchEntry walletEntry = wallet.createWalletBatchEntry();
        walletEntry.setTransactionCode(credentialOffer.getTxCode());
        wallet.collectOffer(walletEntry, toUri(credentialOffer.getOfferDeeplink()));

        // Then
        final var transactionCodeMetadata = walletEntry.getCredentialOffer().getTransactionCodeMetadata();
        assertThat(transactionCodeMetadata)
                .as("transaction-code metadata in the credential offer")
                .isNotNull();
        final String effectiveInputMode = transactionCodeMetadata.has("input_mode")
                ? transactionCodeMetadata.get("input_mode").getAsString()
                : "numeric";
        assertThat(effectiveInputMode)
                .as("effective OID4VCI input mode, using the numeric default when omitted")
                .isEqualTo("numeric");
        assertThat(transactionCodeMetadata.get("length").getAsInt())
                .isEqualTo(6);
        assertThat(transactionCodeMetadata.entrySet())
                .as("public transaction-code metadata must not expose the out-of-band code")
                .noneMatch(entry -> entry.getValue().isJsonPrimitive()
                        && credentialOffer.getTxCode().equals(entry.getValue().getAsString()));
        assertThat(walletEntry.getToken().getTokenType())
                .isEqualTo("DPoP");
        SdJwtBatchAssert.assertThat(walletEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique();
        issuerManager.verifyStatus(credentialOffer.getManagementId(), CredentialStatusType.ISSUED);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1359",
            summary = "Reject invalid transaction codes and permanently lock the offer after five failed attempts",
            description = """
                    Verifies retry after a mistyped transaction code, rejection of missing and malformed values,
                    invalid_tx_code responses for all five allowed attempts, invalid_grant on any subsequent request,
                    and terminal offer lockout even if the correct code is subsequently supplied.
                    """)
    @Tag(ReportingTags.UCI_C1)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    void preAuthorizedOffer_whenTransactionCodeAttemptsFail_thenRetryAndLockoutAreEnforced() {
        // Given a retryable offer
        final CredentialWithDeeplinkResponse retryableOffer = issuerManager.createCredentialOfferWithTransactionCode(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        assertThat(retryableOffer.getTxCode())
                .as("transaction code returned to the Business Issuer")
                .matches("^[0-9]{6}$");
        final String firstWrongCode = ZERO_TRANSACTION_CODE.equals(retryableOffer.getTxCode())
                ? "999999"
                : ZERO_TRANSACTION_CODE;
        final WalletBatchEntry retryableWalletEntry = wallet.createWalletBatchEntry();

        // When the holder mistypes the code once
        retryableWalletEntry.setTransactionCode(firstWrongCode);
        final HttpClientErrorException retryableException = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.collectOffer(retryableWalletEntry, toUri(retryableOffer.getOfferDeeplink())));

        // Then another attempt remains possible
        // The Swiss product profile uses invalid_tx_code to distinguish retryable failures from terminal lockout.
        ApiErrorAssert.assertThat(retryableException)
                .hasStatus(400)
                .hasError("invalid_tx_code");
        assertThat(retryableException.getResponseHeaders())
                .isNotNull();
        assertThat(retryableException.getResponseHeaders().getContentType())
                .isNotNull()
                .satisfies(contentType ->
                        assertThat(MediaType.APPLICATION_JSON.isCompatibleWith(contentType))
                                .isTrue());
        final WalletBatchEntry successfulRetryWalletEntry = wallet.createWalletBatchEntry();
        successfulRetryWalletEntry.setTransactionCode(retryableOffer.getTxCode());
        wallet.collectOffer(successfulRetryWalletEntry, toUri(retryableOffer.getOfferDeeplink()));
        assertThat(successfulRetryWalletEntry.getToken().getAccessToken())
                .isNotBlank();
        assertThat(successfulRetryWalletEntry.getToken().getTokenType())
                .isEqualTo("DPoP");
        issuerManager.verifyStatus(retryableOffer.getManagementId(), CredentialStatusType.ISSUED);

        // Given a second offer that will reach the retry limit
        final CredentialWithDeeplinkResponse lockedOffer = issuerManager.createCredentialOfferWithTransactionCode(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        assertThat(lockedOffer.getTxCode())
                .as("transaction code returned to the Business Issuer")
                .matches("^[0-9]{6}$");
        final String lockedOfferWrongCode = ZERO_TRANSACTION_CODE.equals(lockedOffer.getTxCode())
                ? "999999"
                : ZERO_TRANSACTION_CODE;
        final String[] invalidTransactionCodes = {
                null,
                "ABCDEF",
                "12345",
                lockedOfferWrongCode,
                lockedOfferWrongCode
        };

        // When all five allowed attempts are invalid
        for (String invalidTransactionCode : invalidTransactionCodes) {
            final WalletBatchEntry invalidCodeWalletEntry = wallet.createWalletBatchEntry();
            invalidCodeWalletEntry.setTransactionCode(invalidTransactionCode);
            final HttpClientErrorException invalidCodeException = assertThrows(
                    HttpClientErrorException.class,
                    () -> wallet.collectOffer(invalidCodeWalletEntry, toUri(lockedOffer.getOfferDeeplink())));

            // Then the attempted transaction code is rejected without exposing the expected value
            ApiErrorAssert.assertThat(invalidCodeException)
                    .hasStatus(400)
                    .hasError("invalid_tx_code");
            assertThat(invalidCodeException.getResponseHeaders())
                    .isNotNull();
            assertThat(invalidCodeException.getResponseHeaders().getContentType())
                    .isNotNull()
                    .satisfies(contentType ->
                            assertThat(MediaType.APPLICATION_JSON.isCompatibleWith(contentType))
                                    .isTrue());
        }

        // When the correct code is submitted as the sixth attempt
        final WalletBatchEntry lockedOfferWalletEntry = wallet.createWalletBatchEntry();
        lockedOfferWalletEntry.setTransactionCode(lockedOffer.getTxCode());
        final HttpClientErrorException lockedOfferException = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.collectOffer(lockedOfferWalletEntry, toUri(lockedOffer.getOfferDeeplink())));

        // Then the offer is permanently invalidated regardless of the now-correct code
        ApiErrorAssert.assertThat(lockedOfferException)
                .hasStatus(400)
                .hasError("invalid_grant");
        assertThat(lockedOfferException.getResponseHeaders())
                .isNotNull();
        assertThat(lockedOfferException.getResponseHeaders().getContentType())
                .isNotNull()
                .satisfies(contentType ->
                        assertThat(MediaType.APPLICATION_JSON.isCompatibleWith(contentType))
                                .isTrue());
        assertThat(issuerManager.getCredentialOfferStatusById(
                lockedOffer.getManagementId(), lockedOffer.getOfferId()).getStatus())
                .as("offer is in a terminal invalidated state")
                .isIn(CredentialStatusType.CANCELLED, CredentialStatusType.EXPIRED);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Consume a transaction-code-protected pre-authorized code only once under concurrent requests",
            description = """
                    Verifies that two concurrent DPoP-protected token requests using the same pre-authorized_code and
                    valid tx_code cannot both succeed. Exactly one access token is returned, the competing request is
                    rejected with invalid_grant, and the successful token remains usable for credential issuance.
                    """)
    @Tag(ReportingTags.UCI_C1)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    void preAuthorizedOffer_whenValidTokenRequestsRace_thenCodeIsConsumedOnlyOnce() throws Exception {
        // Given
        final CredentialWithDeeplinkResponse credentialOffer = issuerManager.createCredentialOfferWithTransactionCode(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        assertThat(credentialOffer.getTxCode())
                .as("transaction code returned to the Business Issuer")
                .matches("^[0-9]{6}$");

        final WalletBatchEntry firstWalletEntry = wallet.createWalletBatchEntry();
        firstWalletEntry.receiveDeepLinkAndValidateIt(
                wallet.getIssuerContext().getContextualizedUri(toUri(credentialOffer.getOfferDeeplink())));
        firstWalletEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(firstWalletEntry));
        firstWalletEntry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(firstWalletEntry));
        firstWalletEntry.setTransactionCode(credentialOffer.getTxCode());

        final WalletBatchEntry secondWalletEntry = wallet.createWalletBatchEntry();
        secondWalletEntry.receiveDeepLinkAndValidateIt(
                wallet.getIssuerContext().getContextualizedUri(toUri(credentialOffer.getOfferDeeplink())));
        secondWalletEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(secondWalletEntry));
        secondWalletEntry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(secondWalletEntry));
        secondWalletEntry.setTransactionCode(credentialOffer.getTxCode());

        final String firstDpopNonce = wallet.collectDPoPNonce(firstWalletEntry);
        final String firstDpopProof = DPoPSupport.createDpopProofForToken(
                firstWalletEntry.getIssuerTokenUri().toString(),
                firstDpopNonce,
                wallet.getDpopKeyPair(),
                wallet.getDpopPublicKey());
        final String secondDpopNonce = wallet.collectDPoPNonce(secondWalletEntry);
        final String secondDpopProof = DPoPSupport.createDpopProofForToken(
                secondWalletEntry.getIssuerTokenUri().toString(),
                secondDpopNonce,
                wallet.getDpopKeyPair(),
                wallet.getDpopPublicKey());

        final CyclicBarrier tokenRequestBarrier = new CyclicBarrier(2);
        final Callable<Object> firstTokenRequest = () -> {
            tokenRequestBarrier.await(10, TimeUnit.SECONDS);
            try {
                return wallet.collectTokenWithDPoP(firstWalletEntry, firstDpopProof);
            } catch (HttpClientErrorException exception) {
                return exception;
            }
        };
        final Callable<Object> secondTokenRequest = () -> {
            tokenRequestBarrier.await(10, TimeUnit.SECONDS);
            try {
                return wallet.collectTokenWithDPoP(secondWalletEntry, secondDpopProof);
            } catch (HttpClientErrorException exception) {
                return exception;
            }
        };

        // When
        final List<Object> tokenRequestResults;
        try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
            final var firstResult = executor.submit(firstTokenRequest);
            final var secondResult = executor.submit(secondTokenRequest);
            tokenRequestResults = List.of(
                    firstResult.get(30, TimeUnit.SECONDS),
                    secondResult.get(30, TimeUnit.SECONDS));
        }

        // Then
        final List<OAuthToken> issuedTokens = tokenRequestResults.stream()
                .filter(OAuthToken.class::isInstance)
                .map(OAuthToken.class::cast)
                .toList();
        final List<HttpClientErrorException> rejectedRequests = tokenRequestResults.stream()
                .filter(HttpClientErrorException.class::isInstance)
                .map(HttpClientErrorException.class::cast)
                .toList();

        assertThat(issuedTokens)
                .as("access tokens returned for one pre-authorized code")
                .hasSize(1);
        assertThat(issuedTokens.getFirst().getAccessToken())
                .isNotBlank();
        assertThat(issuedTokens.getFirst().getTokenType())
                .isEqualTo("DPoP");
        assertThat(rejectedRequests)
                .as("concurrent token requests rejected after the code was consumed")
                .hasSize(1);
        ApiErrorAssert.assertThat(rejectedRequests.getFirst())
                .hasStatus(400)
                .hasError("invalid_grant");

        firstWalletEntry.setToken(issuedTokens.getFirst());
        firstWalletEntry.generateHolderKeys(CredentialConfigurationFixtures.BATCH_SIZE);
        firstWalletEntry.setCNonce(wallet.collectCNonce(firstWalletEntry));
        firstWalletEntry.createProofs();
        final List<String> issuedCredentials = wallet.getVerifiableCredentialFromIssuer(firstWalletEntry);

        SdJwtBatchAssert.assertThat(issuedCredentials)
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique();
        issuerManager.verifyStatus(credentialOffer.getManagementId(), CredentialStatusType.ISSUED);
    }
}
