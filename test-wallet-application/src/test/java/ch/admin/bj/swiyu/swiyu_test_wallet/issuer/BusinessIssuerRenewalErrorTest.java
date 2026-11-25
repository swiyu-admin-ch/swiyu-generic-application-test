package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.WebhookCallback;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.UseWallet;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockserver.matchers.MatchType;
import org.mockserver.matchers.TimeToLive;
import org.mockserver.matchers.Times;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClientResponseException;
import tools.jackson.databind.ObjectMapper;

import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.mockserver.model.JsonBody.json;

/** Exercises renewal denial across the Business Issuer, Credential Issuer and Wallet boundaries. */
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.RENEWAL_DEFAULT)
@UseWallet(dpop = true, encryption = true, signedMetadata = true)
@Tag(ReportingTags.EDGE_CASE)
@Tag(ReportingTags.UCI_I1E_RENEW_VERIFIABLE_CREDENTIALS)
class BusinessIssuerRenewalErrorTest extends BaseTest {

    @ParameterizedTest(name = "Business Issuer HTTP {0} is logged at {1}")
    @CsvSource({
            "420, INFO",
            "451, INFO",
            "500, INFO",
            "503, INFO",
            "404, ERROR",
            "409, ERROR",
            "400, ERROR",
            "401, ERROR",
            "429, ERROR",
            "502, ERROR"
    })
    @XrayTest(
            key = "EIDOMNI-1561",
            summary = "Credential Issuer logs Business Issuer renewal denials at the required level and informs the Wallet",
            description = """
                    Given an issued batch and a Wallet using DPoP, response encryption and signed metadata.
                    When the Business Issuer returns an error to the renewal callback.
                    Then the Credential Issuer logs 420, 451, 500 and 503 at INFO, and 404, 409 and other errors at ERROR.
                    It returns the Business Issuer HTTP status and an unencrypted credential_request_denied to the Wallet,
                    creates no new batch or status references, preserves the issued family and sends no issuance callback.
                    Spec: EIDOMNI-1344 supplied Arc42 error-handling decision (log levels and HTTP status propagation);
                    Swiss issuance profile section 14.5; OID4VCI 1.0 section 8.3.1.2 (error body and no encryption).
                    """)
    @DisableIfImageTag(issuer = {ImageTags.STABLE, ImageTags.RC},
            reason = "Requires EIDOMNI-1344 business-issuer renewal log levels")
    void credentialRenewal_whenBusinessIssuerReturnsError_thenLogsAtRequiredLevelAndPreservesIssuedBatch(
            final int statusCode, final String expectedLogLevel) throws SQLException {
        // Given
        final var offer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                CredentialSubjectFixtures.completeEmployeeProfile());
        final var initialEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final var initialCredentials = List.copyOf(initialEntry.getIssuedCredentials());
        assertThat(initialCredentials)
                .hasSize(initialEntry.getIssuerMetadata().getBatchCredentialIssuance().getBatchSize());
        final var renewalEntry = initialEntry.duplicate();
        final var managementBefore = issuerManager.getCredentialById(offer.getManagementId());
        final var referencesBefore = credentialStatusReferences(offer.getManagementId());
        cleanIssuerCallbacks();

        final var renewalRequest = request().withMethod("POST").withPath("/renewal")
                .withBody(json("{\"management_id\":\"" + offer.getManagementId() + "\"}", MatchType.ONLY_MATCHING_FIELDS));
        final var expectations = mockServerClient.when(renewalRequest,
                        Times.unlimited(), TimeToLive.unlimited(), 100)
                .respond(response().withStatusCode(statusCode));
        final int logOffset = issuerContainer.getLogs().length();

        try {
            // When
            final var exception = assertThrows(RestClientResponseException.class,
                    () -> wallet.renewedCredentials(renewalEntry));

            // Then
            assertThat(exception.getStatusCode().value())
                    .isEqualTo(statusCode);
            assertThat(exception.getResponseHeaders())
                    .isNotNull();
            assertThat(exception.getResponseHeaders().getContentType())
                    .isNotNull()
                    .matches(type -> type.isCompatibleWith(MediaType.APPLICATION_JSON),
                            "Credential Error Responses are unencrypted JSON (OID4VCI 8.3.1.2)");
            assertThat(new ObjectMapper().readValue(exception.getResponseBodyAsString(), Map.class))
                    .containsEntry("error", "credential_request_denied")
                    .containsEntry("error_description", "Renewal request failed");
            assertThat(mockServerClient.retrieveRecordedRequests(renewalRequest))
                    .as("Exactly one renewal request reaches the Business Issuer, without an automatic retry")
                    .hasSize(1);

            await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
                final var renewalLogs = issuerContainer.getLogs().substring(logOffset).lines()
                        .filter(line -> line.contains("BusinessIssuerRenewalApiClient"))
                        .filter(line -> line.contains("Renewal request to "))
                        .toList();
                assertThat(renewalLogs)
                        .singleElement()
                        .satisfies(line -> assertThat(line)
                                .containsPattern("\\b" + expectedLogLevel + "\\b")
                                .contains("/renewal", "failed with status code " + statusCode));
            });

            final var managementAfter = issuerManager.getCredentialById(offer.getManagementId());
            assertThat(managementAfter.getStatus())
                    .isEqualTo(CredentialStatusType.ISSUED);
            assertThat(managementAfter.getCredentialOffers())
                    .containsExactlyInAnyOrderElementsOf(managementBefore.getCredentialOffers());
            assertThat(managementAfter.getRenewalRequestCount())
                    .isEqualTo(managementBefore.getRenewalRequestCount());
            assertThat(managementAfter.getRenewalResponseCount())
                    .isEqualTo(managementBefore.getRenewalResponseCount());
            assertThat(credentialStatusReferences(offer.getManagementId()))
                    .containsExactlyElementsOf(referencesBefore);
            assertThat(renewalEntry.getIssuedCredentials())
                    .isEmpty();
            assertThat(initialEntry.getIssuedCredentials())
                    .containsExactlyElementsOf(initialCredentials);
            awaitStableIssuerCallbacks();
            assertThat(issuerCallbacks())
                    .noneMatch(callback -> callback.getEventType() == WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED
                            && "ISSUED".equals(callback.getEvent()));
            if ("INFO".equals(expectedLogLevel)) {
                assertThat(issuerContainer.getLogs().substring(logOffset))
                        .as("An expected Business Issuer denial must not produce a secondary ERROR log")
                        .doesNotContainPattern("\\bERROR\\b");
            }
        } finally {
            for (final var expectation : expectations) {
                mockServerClient.clear(expectation.getId());
            }
        }
    }

    private List<String> credentialStatusReferences(final UUID managementId) throws SQLException {
        final String schema = currentIssuer.imageConfig().getDbSchema();
        final String sql = "SELECT s.status_list_id, s.index FROM " + schema + ".credential_offer_status s JOIN "
                + schema + ".credential_offer o ON o.id = s.credential_offer_id "
                + "WHERE o.credential_management_id = ? ORDER BY s.status_list_id, s.index";
        try (var statement = connection.prepareStatement(sql)) {
            statement.setObject(1, managementId);
            try (var result = statement.executeQuery()) {
                final List<String> references = new ArrayList<>();
                while (result.next()) {
                    references.add(result.getString(1) + ":" + result.getInt(2));
                }
                return references;
            }
        }
    }
}
