package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto.DPoPSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockserver.matchers.MatchType;
import org.mockserver.matchers.TimeToLive;
import org.mockserver.matchers.Times;
import org.mockserver.model.HttpRequest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.mock.MockServices.ISSUER_CALLBACK_PATH;
import static ch.admin.bj.swiyu.swiyu_test_wallet.fixture.RenewalApiKeyFixtures.RENEWAL_HEADER;
import static ch.admin.bj.swiyu.swiyu_test_wallet.fixture.RenewalApiKeyFixtures.RENEWAL_VALUE;
import static ch.admin.bj.swiyu.swiyu_test_wallet.fixture.RenewalApiKeyFixtures.WEBHOOK_HEADER;
import static ch.admin.bj.swiyu.swiyu_test_wallet.fixture.RenewalApiKeyFixtures.WEBHOOK_VALUE;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.mockserver.model.JsonBody.json;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers({IssuerVariant.RENEWAL_API_KEY, IssuerVariant.RENEWAL_WEBHOOK_ONLY})
@Tag(ReportingTags.UCI_I2)
class RenewalApiKeyTest extends BaseTest {

    @Test
    @Tag(ReportingTags.HAPPY_PATH)
    @XrayTest(key = "EIDOMNI-1378",
            summary = "Renewal uses its dedicated API key independently of webhooks",
            description = "Complete issuance and renewal against an authenticated Business Issuer mock. "
                    + "Check the exact custom renewal header, webhook authentication and isolation of both keys.")
    void renewal_whenApiKeyConfigured_thenAuthenticatesWithoutSharingWebhookKey() {
        // Given
        useIssuer(issuer(IssuerVariant.RENEWAL_API_KEY));
        wallet.setUseDPoP(true);
        final var offer = issuerManager.createCredentialWithSignedJwt(
                jwtKey, keyId, CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final var entry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final var renewalRequest = renewalRequest(offer.getManagementId());
        final String renewalBody = new ObjectMapper().writeValueAsString(Map.of(
                "metadata_credential_supported_id", List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT),
                "credential_subject_data", CredentialSubjectFixtures.completeEmployeeProfile(),
                "credential_valid_from", Instant.now().minusSeconds(60).truncatedTo(ChronoUnit.SECONDS).toString(),
                "credential_valid_until", Instant.now().plusSeconds(3600).truncatedTo(ChronoUnit.SECONDS).toString(),
                "status_lists", List.of(getCurrentStatusList().getStatusRegistryUrl())));
        final var expectations = mockServerClient
                .when(renewalRequest, Times.unlimited(), TimeToLive.unlimited(), 100)
                .respond(incoming -> {
                    if (!incoming.getHeader(RENEWAL_HEADER).equals(List.of(RENEWAL_VALUE))) {
                        return response().withStatusCode(401);
                    }
                    return response().withStatusCode(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody(renewalBody);
                });

        try {
            // When
            refreshAccessToken(entry);
            final var renewed = wallet.renewedCredentials(entry);

            // Then
            assertThat(renewed.getStatus())
                    .isEqualTo(200);
            assertThat(entry.getIssuedCredentials())
                    .hasSize(CredentialConfigurationFixtures.BATCH_SIZE * 2)
                    .doesNotHaveDuplicates();
            final var management = issuerManager.getCredentialById(offer.getManagementId());
            assertThat(management.getStatus())
                    .isEqualTo(CredentialStatusType.ISSUED);
            assertThat(management.getCredentialOffers())
                    .hasSize(2)
                    .allSatisfy(issuedOffer -> assertThat(issuedOffer.getStatus())
                            .isEqualTo(CredentialStatusType.ISSUED));
            assertThat(management.getRenewalResponseCount())
                    .isEqualTo(1);
            assertThat(mockServerClient.retrieveRecordedRequests(renewalRequest))
                    .hasSize(1)
                    .allSatisfy(incoming -> {
                        assertThat(incoming.getHeader(RENEWAL_HEADER))
                                .containsExactly(RENEWAL_VALUE);
                        assertThat(incoming.getHeader(WEBHOOK_HEADER))
                                .isEmpty();
                    });
            await().atMost(Duration.ofSeconds(30)).untilAsserted(() ->
                    assertThat(mockServerClient.retrieveRecordedRequests(issuedCallback(offer.getManagementId())))
                            .isNotEmpty()
                            .allSatisfy(callback -> {
                                assertThat(callback.getHeader(WEBHOOK_HEADER))
                                        .containsExactly(WEBHOOK_VALUE);
                                assertThat(callback.getHeader(RENEWAL_HEADER))
                                        .isEmpty();
                            }));
        } finally {
            mockServerClient.clear(expectations[0].getId());
        }
    }

    @Test
    @Tag(ReportingTags.EDGE_CASE)
    @XrayTest(key = "EIDOMNI-1379",
            summary = "Unconfigured renewal API key preserves existing integrations",
            description = "Leave both renewal key properties unset while configuring webhook authentication. "
                    + "Renewal must succeed without a renewal header or fallback to the webhook key.")
    void renewal_whenApiKeyUnset_thenSucceedsWithoutFallingBackToWebhookKey() {
        // Given
        useIssuer(issuer(IssuerVariant.RENEWAL_WEBHOOK_ONLY));
        wallet.setUseDPoP(true);
        final var offer = issuerManager.createCredentialWithSignedJwt(
                jwtKey, keyId, CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final var entry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        // When
        refreshAccessToken(entry);
        final var renewed = wallet.renewedCredentials(entry);

        // Then
        assertThat(renewed.getStatus())
                .isEqualTo(200);
        assertThat(entry.getIssuedCredentials())
                .hasSize(CredentialConfigurationFixtures.BATCH_SIZE * 2)
                .doesNotHaveDuplicates();
        final var management = issuerManager.getCredentialById(offer.getManagementId());
        assertThat(management.getStatus())
                .isEqualTo(CredentialStatusType.ISSUED);
        assertThat(management.getCredentialOffers())
                .hasSize(2)
                .allSatisfy(issuedOffer -> assertThat(issuedOffer.getStatus())
                        .isEqualTo(CredentialStatusType.ISSUED));
        assertThat(management.getRenewalResponseCount())
                .isEqualTo(1);
        assertThat(mockServerClient.retrieveRecordedRequests(renewalRequest(offer.getManagementId())))
                .hasSize(1)
                .allSatisfy(incoming -> {
                    assertThat(incoming.getHeader(RENEWAL_HEADER))
                            .isEmpty();
                    assertThat(incoming.getHeader(WEBHOOK_HEADER))
                            .isEmpty();
                    assertThat(incoming.getHeader("Authorization"))
                            .isEmpty();
                });
        await().atMost(Duration.ofSeconds(30)).untilAsserted(() ->
                assertThat(mockServerClient.retrieveRecordedRequests(issuedCallback(offer.getManagementId())))
                        .isNotEmpty()
                        .allSatisfy(callback -> {
                            assertThat(callback.getHeader(WEBHOOK_HEADER))
                                    .containsExactly(WEBHOOK_VALUE);
                            assertThat(callback.getHeader(RENEWAL_HEADER))
                                    .isEmpty();
                        }));
    }

    private void refreshAccessToken(final WalletBatchEntry entry) {
        final String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(), wallet.collectDPoPNonce(entry),
                wallet.getDpopKeyPair(), wallet.getDpopPublicKey(), entry.getToken().getRefreshToken());
        entry.setToken(wallet.collectRefreshTokenWithDPoP(entry, dpop));
    }

    private HttpRequest renewalRequest(final UUID managementId) {
        return request().withMethod("POST").withPath("/renewal")
                .withBody(json("{\"management_id\":\"" + managementId + "\"}", MatchType.ONLY_MATCHING_FIELDS));
    }

    private HttpRequest issuedCallback(final UUID managementId) {
        return request().withMethod("POST").withPath(ISSUER_CALLBACK_PATH)
                .withBody(json("""
                        {"subject_id":"%s","event":"ISSUED","event_trigger":"CREDENTIAL_MANAGEMENT"}
                        """.formatted(managementId), MatchType.ONLY_MATCHING_FIELDS));
    }
}
