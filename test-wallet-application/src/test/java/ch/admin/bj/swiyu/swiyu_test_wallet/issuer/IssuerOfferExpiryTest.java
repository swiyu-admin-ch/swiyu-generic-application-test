package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.sql.SQLException;
import java.time.Instant;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class IssuerOfferExpiryTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Issuer rejects the Pre-Authorized Code of an expired credential offer",
            description = """
                    Given a non-deferred credential offer whose offer deadline has passed before the wallet redeems it.
                    When the wallet sends the Token Request with the Pre-Authorized Code of that offer.
                    Then the Issuer rejects the request with HTTP 400 invalid_grant, the offer is EXPIRED and no
                    credential is issued.
                    Spec: OID4VCI 1.0 §4.1.1 and §6.3; RFC 6749 §5.2 (invalid_grant: expired authorization grant).
                    """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    void tokenRequest_whenOfferExpiredBeforeRedemption_thenInvalidGrantAndNoIssuance() throws SQLException {
        // Given
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
        );
        final WalletBatchEntry batchEntry = new WalletBatchEntry(wallet);
        batchEntry.receiveDeepLinkAndValidateIt(toUri(offer.getOfferDeeplink()));
        batchEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(batchEntry));
        batchEntry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(batchEntry));
        batchEntry.setCredentialConfigurationSupported();
        expireOffer(offer);

        // When
        final HttpClientErrorException exception = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.collectToken(batchEntry)
        );

        // Then
        ApiErrorAssert.assertThat(exception)
                .hasStatus(400)
                .hasError("invalid_grant");
        assertThat(issuerManager.getStatusById(offer.getManagementId()).getStatus())
                .isEqualTo(CredentialStatusType.EXPIRED);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Issuer denies the Credential Request of an offer that expired after the Token Request",
            description = """
                    Given a non-deferred credential offer for which the wallet already holds a valid access token.
                    When the offer deadline passes and the wallet then sends the Credential Request.
                    Then the Issuer denies the request with HTTP 400 credential_request_denied, the offer is EXPIRED
                    and no credential is issued.
                    Spec: OID4VCI 1.0 §8.3.1.2 (credential_request_denied).
                    """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    void credentialRequest_whenOfferExpiredAfterTokenRequest_thenDeniedAndNoIssuance() throws SQLException {
        // Given
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
        );
        final WalletBatchEntry batchEntry = wallet.prepareOffer(toUri(offer.getOfferDeeplink()));
        expireOffer(offer);

        // When
        final HttpClientErrorException exception = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.postCredentialRequest(batchEntry)
        );

        // Then
        ApiErrorAssert.assertThat(exception)
                .hasStatus(400)
                .hasError("credential_request_denied");
        assertThat(batchEntry.getIssuedCredentials())
                .isEmpty();
        assertThat(issuerManager.getStatusById(offer.getManagementId()).getStatus())
                .isEqualTo(CredentialStatusType.EXPIRED);
    }

    /** Moves only this offer's deadline into the past; no scheduler or concurrent request is involved. */
    private void expireOffer(final CredentialWithDeeplinkResponse offer) throws SQLException {
        final String schema = currentIssuer.imageConfig().getDbSchema();
        try (var statement = connection.prepareStatement("UPDATE " + schema
                + ".credential_offer SET offer_expiration_timestamp = ? WHERE id = ? AND credential_management_id = ?")) {
            statement.setLong(1, Instant.now().minusSeconds(1).getEpochSecond());
            statement.setObject(2, offer.getOfferId());
            statement.setObject(3, offer.getManagementId());
            assertThat(statement.executeUpdate())
                    .isEqualTo(1);
        }
    }
}
