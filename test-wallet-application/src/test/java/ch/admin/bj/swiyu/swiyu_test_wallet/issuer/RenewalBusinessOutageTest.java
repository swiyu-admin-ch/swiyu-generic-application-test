package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.issuer.model.WebhookCallback;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_response.CredentialResponseAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.UseWallet;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockserver.matchers.MatchType;
import org.mockserver.matchers.TimeToLive;
import org.mockserver.matchers.Times;
import org.mockserver.model.ClearType;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpServerErrorException;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.mockserver.model.JsonBody.json;

/**
 * Checks renewal recovery across the Wallet, Generic Issuer and Business Issuer boundaries.
 * The explicit retry probes issuer recovery; it does not model an automatic Wallet retry policy.
 */
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.RENEWAL_PERMISSIVE_EXPERIMENTAL)
@UseWallet(dpop = true, encryption = true, signedMetadata = true)
@Tag(ReportingTags.UCI_I1)
@Tag(ReportingTags.EDGE_CASE)
class RenewalBusinessOutageTest extends BaseTest {

    @ParameterizedTest(name = "[{index}] renewal recovery for {0}")
    @EnumSource(value = CredentialStatusType.class, names = {"ISSUED", "SUSPENDED"})
    @XrayTest(key = "EIDOMNI-1086",
            summary = "Credential Issuer preserves renewal eligibility after a temporary Business Issuer outage",
            description = """
                    Given an issued or suspended family with experimental suspended renewal enabled.
                    When the Business Issuer returns HTTP 503 for one renewal and then recovers.
                    Then the Wallet receives HTTP 503 without a partial batch or successful issuance callback, and a fresh
                    Wallet request using the same access token obtains one complete encrypted batch.
                    The family keeps its status. The HTTP 503 response body is left unconstrained.
                    Spec: RFC 9110 section 15.6.4 (503; Retry-After MAY be sent);
                    Swiss issuance profile section 14.5. No Retry-After header is required by this test.
                    """)
    void credentialRenewal_whenBusinessIssuerRecoversFrom503_thenRetrySucceeds(
            final CredentialStatusType initialStatus) throws SQLException {
        // Given
        useIssuer(issuer(IssuerVariant.RENEWAL_PERMISSIVE_EXPERIMENTAL));
        final var offer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                CredentialSubjectFixtures.completeEmployeeProfile());
        final var initialEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final var initialCredentials = List.copyOf(initialEntry.getIssuedCredentials());
        if (initialStatus == CredentialStatusType.SUSPENDED) {
            issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.SUSPENDED);
        }
        final var managementBefore = issuerManager.getCredentialById(offer.getManagementId());
        final var referencesBefore = credentialStatusReferences(offer.getManagementId());
        assertThat(managementBefore.getStatus())
                .isEqualTo(initialStatus);
        awaitStableIssuerCallbacks();
        final var issuedCallbacksBefore = issuerCallbacks().stream()
                .filter(callback -> callback.getEventType() == WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                .filter(callback -> "ISSUED".equals(callback.getEvent()))
                .toList();
        final var renewalRequest = request()
                .withMethod("POST")
                .withPath("/renewal")
                .withBody(json("{\"management_id\":\"" + offer.getManagementId() + "\"}",
                        MatchType.ONLY_MATCHING_FIELDS));
        assertThat(mockServerClient.retrieveRecordedRequests(renewalRequest))
                .isEmpty();
        final var failedRenewalEntry = initialEntry.duplicate();
        final var outage = mockServerClient.when(renewalRequest,
                        Times.exactly(1), TimeToLive.unlimited(), 100)
                .respond(response().withStatusCode(503)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"message\":\"Business Issuer temporarily unavailable\"}"));

        // When: only this family's next renewal encounters the outage.
        final HttpServerErrorException failure;
        try {
            failure = assertThrows(HttpServerErrorException.class,
                    () -> wallet.renewedCredentials(failedRenewalEntry));
        } finally {
            mockServerClient.clear(outage[0].getId(), ClearType.EXPECTATIONS);
        }

        // Then: the failure rolls back the tentative offer, counters and status references.
        assertThat(failure.getStatusCode().value())
                .isEqualTo(503);
        final var managementAfterFailure = issuerManager.getCredentialById(offer.getManagementId());
        assertThat(managementAfterFailure.getStatus())
                .isEqualTo(initialStatus);
        assertThat(managementAfterFailure.getCredentialOffers())
                .containsExactlyInAnyOrderElementsOf(managementBefore.getCredentialOffers());
        assertThat(managementAfterFailure.getRenewalRequestCount())
                .isEqualTo(managementBefore.getRenewalRequestCount());
        assertThat(managementAfterFailure.getRenewalResponseCount())
                .isEqualTo(managementBefore.getRenewalResponseCount());
        assertThat(credentialStatusReferences(offer.getManagementId()))
                .containsExactlyElementsOf(referencesBefore);
        assertThat(failedRenewalEntry.getIssuedCredentials())
                .isEmpty();
        assertThat(mockServerClient.retrieveRecordedRequests(renewalRequest))
                .hasSize(1);
        awaitStableIssuerCallbacks();
        assertThat(issuerCallbacks().stream()
                .filter(callback -> callback.getEventType() == WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                .filter(callback -> "ISSUED".equals(callback.getEvent()))
                .toList())
                .containsExactlyElementsOf(issuedCallbacksBefore);

        // When: the normal Business Issuer mock is available again; use fresh proofs with the same access token.
        final var retryEntry = initialEntry.duplicate();
        final var recoveredResponse = wallet.renewedCredentials(retryEntry);

        // Then
        CredentialResponseAssert.assertThat(recoveredResponse)
                .hasCode(200)
                .hasNotTransactionId()
                .isResponseEncrypted();
        assertThat(retryEntry.getToken().getAccessToken())
                .isEqualTo(initialEntry.getToken().getAccessToken());
        assertThat(retryEntry.getProofs())
                .hasSize(initialCredentials.size());
        SdJwtBatchAssert.assertThat(retryEntry.getIssuedCredentials())
                .hasBatchSize(retryEntry.getProofs().size())
                .areUnique()
                .haveUniqueHolderBindingKeys()
                .haveUniqueStatusListIndexes()
                .haveDisclosuresBoundToPayloadDigests()
                .allHaveExactlyInAnyOrderDisclosures(CredentialSubjectFixtures.completeEmployeeProfile());
        assertThat(initialEntry.getIssuedCredentials())
                .containsExactlyElementsOf(initialCredentials);
        assertThat(retryEntry.getIssuedCredentials())
                .doesNotContainAnyElementsOf(initialCredentials);
        final var managementAfterRecovery = issuerManager.getCredentialById(offer.getManagementId());
        assertThat(managementAfterRecovery.getStatus())
                .isEqualTo(initialStatus);
        assertThat(managementAfterRecovery.getCredentialOffers())
                .hasSize(managementBefore.getCredentialOffers().size() + 1)
                .containsAll(managementBefore.getCredentialOffers());
        assertThat(managementAfterRecovery.getRenewalRequestCount())
                .isEqualTo(managementBefore.getRenewalRequestCount() + 1);
        assertThat(managementAfterRecovery.getRenewalResponseCount())
                .isEqualTo(managementBefore.getRenewalResponseCount() + 1);
        assertThat(credentialStatusReferences(offer.getManagementId()))
                .hasSize(referencesBefore.size() + retryEntry.getProofs().size())
                .containsAll(referencesBefore)
                .doesNotHaveDuplicates();
        assertThat(mockServerClient.retrieveRecordedRequests(renewalRequest))
                .hasSize(2);
        awaitStableIssuerCallbacks();
        assertThat(issuerCallbacks().stream()
                .filter(callback -> callback.getEventType() == WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                .filter(callback -> "ISSUED".equals(callback.getEvent()))
                .toList())
                .hasSize(issuedCallbacksBefore.size() + 1)
                .containsAll(issuedCallbacksBefore);
    }

    /** Reads persisted status references to detect an otherwise invisible partial renewal. */
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
