package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.DEFAULT)
class TransactionCodeTest extends BaseTest {

    private static final String ZERO_TRANSACTION_CODE = "000000";

    @BeforeAll
    void useDpopForTokenRequests() {
        wallet.setUseDPoP(true);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Redeem a pre-authorized credential offer with a valid transaction code",
            description = """
                    Verifies that transaction codes are enabled by default, returned to the Business Issuer as a
                    six-digit numeric value, advertised in the credential offer, and accepted together with a
                    DPoP-protected pre-authorized code token request.
                    """)
    @Tag(ReportingTags.UCI_C1)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.HAPPY_PATH)
    void preAuthorizedOffer_whenTransactionCodeIsValid_thenCredentialIsIssued() {
        // Given
        final CredentialWithDeeplinkResponse credentialOffer = issuerManager.createCredentialOffer(
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
        assertThat(transactionCodeMetadata.get("input_mode").getAsString())
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
            key = "EIDOMNI-XXX",
            summary = "Reject invalid transaction codes and permanently lock the offer after five failed attempts",
            description = """
                    Verifies retry after a mistyped transaction code, rejection of missing and malformed values,
                    invalid_tx_code responses before the configured default limit, invalid_grant on the fifth failure,
                    and terminal offer lockout even if the correct code is subsequently supplied.
                    """)
    @Tag(ReportingTags.UCI_C1)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    void preAuthorizedOffer_whenTransactionCodeAttemptsFail_thenRetryAndLockoutAreEnforced() {
        // Given a retryable offer
        final CredentialWithDeeplinkResponse retryableOffer = issuerManager.createCredentialOffer(
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
        final CredentialWithDeeplinkResponse lockedOffer = issuerManager.createCredentialOffer(
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
                lockedOfferWrongCode
        };

        // When the first four attempts are invalid
        for (String invalidTransactionCode : invalidTransactionCodes) {
            final WalletBatchEntry invalidCodeWalletEntry = wallet.createWalletBatchEntry();
            invalidCodeWalletEntry.setTransactionCode(invalidTransactionCode);
            final HttpClientErrorException invalidCodeException = assertThrows(
                    HttpClientErrorException.class,
                    () -> wallet.collectOffer(invalidCodeWalletEntry, toUri(lockedOffer.getOfferDeeplink())));

            // Then the Wallet can still retry
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

        // When the fifth attempt is invalid
        final WalletBatchEntry retryLimitWalletEntry = wallet.createWalletBatchEntry();
        retryLimitWalletEntry.setTransactionCode(lockedOfferWrongCode);
        final HttpClientErrorException retryLimitException = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.collectOffer(retryLimitWalletEntry, toUri(lockedOffer.getOfferDeeplink())));

        // Then the offer is permanently invalidated
        ApiErrorAssert.assertThat(retryLimitException)
                .hasStatus(400)
                .hasError("invalid_grant");
        assertThat(retryLimitException.getResponseHeaders())
                .isNotNull();
        assertThat(retryLimitException.getResponseHeaders().getContentType())
                .isNotNull()
                .satisfies(contentType ->
                        assertThat(MediaType.APPLICATION_JSON.isCompatibleWith(contentType))
                                .isTrue());
        assertThat(issuerManager.getCredentialOfferStatusById(
                lockedOffer.getManagementId(), lockedOffer.getOfferId()).getStatus())
                .isEqualTo(CredentialStatusType.EXPIRED);

        final WalletBatchEntry lockedOfferWalletEntry = wallet.createWalletBatchEntry();
        lockedOfferWalletEntry.setTransactionCode(lockedOffer.getTxCode());
        final HttpClientErrorException lockedOfferException = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.collectOffer(lockedOfferWalletEntry, toUri(lockedOffer.getOfferDeeplink())));
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
                .isEqualTo(CredentialStatusType.EXPIRED);
    }
}
