package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.DPoPSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.NO_REFRESH_TOKEN_ROTATION)
class RefreshTokenWithoutRotationTest extends BaseTest {
    @Test
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    @XrayTest(key = "EIDOMNI-1342",
            summary = "Repeated refresh without rotation keeps the refresh token and replaces the access token",
            description = "Sequential baseline for R16: two fresh DPoP proofs use the same refresh token; only the latest access token can renew credentials.")
    @DisableIfImageTag(issuer = {ImageTags.STABLE}, reason = "Requires renewal support, as do the existing refresh token tests")
    void repeatedRefresh_whenRotationDisabled_thenOnlyLatestAccessTokenCanRenew() {
        // Given
        wallet.setUseDPoP(true);
        final var offer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final WalletBatchEntry entry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final String originalRefreshToken = entry.getToken().getRefreshToken();
        final var initialOffers = issuerManager.getCredentialById(offer.getManagementId()).getCredentialOffers();

        // When: distinct proofs, sequential uses of the same refresh token.
        final var firstToken = wallet.collectRefreshTokenWithDPoP(entry, refreshProof(entry));
        entry.setToken(firstToken);
        final var secondToken = wallet.collectRefreshTokenWithDPoP(entry, refreshProof(entry));

        // Then: token refresh does not issue credentials.
        assertThat(originalRefreshToken.equals(firstToken.getRefreshToken())
                && originalRefreshToken.equals(secondToken.getRefreshToken()))
                .as("Both responses retain the original refresh token without printing its value")
                .isTrue();
        assertThat(firstToken.getAccessToken().equals(secondToken.getAccessToken()))
                .as("Each refresh replaces the access token")
                .isFalse();
        assertThat(issuerManager.getCredentialById(offer.getManagementId()).getCredentialOffers())
                .containsExactlyElementsOf(initialOffers);

        final var oldTokenError = assertThrows(HttpClientErrorException.class, () -> wallet.renewedCredentials(entry));
        ApiErrorAssert.assertThat(oldTokenError)
                .hasStatus(400)
                .hasError("invalid_token");
        assertThat(issuerManager.getCredentialById(offer.getManagementId()).getCredentialOffers())
                .containsExactlyElementsOf(initialOffers);

        entry.setToken(secondToken);
        assertThat(wallet.renewedCredentials(entry).getStatus())
                .isEqualTo(200);
        final var management = issuerManager.getCredentialById(offer.getManagementId());
        assertThat(management.getStatus())
                .isEqualTo(CredentialStatusType.ISSUED);
        assertThat(management.getCredentialOffers())
                .hasSize(initialOffers.size() + 1);
        assertThat(management.getRenewalResponseCount())
                .isEqualTo(1);
    }

    private String refreshProof(final WalletBatchEntry entry) {
        return DPoPSupport.createDpopProofForToken(entry.getIssuerTokenUri().toString(),
                wallet.collectDPoPNonce(entry), wallet.getDpopKeyPair(), wallet.getDpopPublicKey(),
                entry.getToken().getRefreshToken());
    }
}
