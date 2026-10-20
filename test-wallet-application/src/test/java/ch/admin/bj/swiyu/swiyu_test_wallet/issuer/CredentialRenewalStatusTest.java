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
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_response.CredentialResponseAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.UseWallet;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockserver.matchers.MatchType;
import org.mockserver.matchers.TimeToLive;
import org.mockserver.matchers.Times;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.security.interfaces.ECPublicKey;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.mockserver.model.JsonBody.json;

/** Renewal eligibility at the Wallet/Credential Issuer boundary, including the experimental suspended-renewal policy. */
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers({IssuerVariant.RENEWAL_DEFAULT, IssuerVariant.RENEWAL_STRICT,
        IssuerVariant.RENEWAL_PERMISSIVE_EXPERIMENTAL})
@UseWallet(dpop = true, encryption = true, signedMetadata = true)
@Tag(ReportingTags.UCI_I1)
@Tag(ReportingTags.EDGE_CASE)
class CredentialRenewalStatusTest extends BaseTest {

    @ParameterizedTest(name = "[{index}] revoked renewal under {0}")
    @EnumSource(value = IssuerVariant.class, names = {
            "RENEWAL_DEFAULT", "RENEWAL_STRICT", "RENEWAL_PERMISSIVE_EXPERIMENTAL"})
    @XrayTest(
            key = "EIDOMNI-1085",
            summary = "Credential Issuer denies renewal of revoked batches under every renewal policy",
            description = """
                    Given an issued batch, a successful renewal, and a still-valid DPoP-bound access token.
                    When the Business Issuer revokes the family and the Wallet attempts renewal from both generations
                    while the public Status List still serves its pre-revocation snapshot.
                    Then the Credential Issuer returns HTTP 400 credential_request_denied as unencrypted JSON,
                    calls no Business Issuer renewal endpoint, creates no offers or status references,
                    and leaves the family REVOKED without a successful issuance callback.
                    The rule also applies with experimental suspended renewal enabled.
                    Deviation: the Status Registry serves a stale, correctly signed Status List Token.
                    Spec: EIDOMNI-1085; OID4VCI 1.0 sections 8.3.1.2 and 14.5;
                    Swiss issuance profile sections 14.5 and 14.6; Swiss VC profile section 7.1 (Status Types Values).
                    """)
    void credentialRenewal_whenRevokedAndPublicStatusIsStale_thenDeniedWithoutSideEffects(
            final IssuerVariant variant) throws SQLException {
        // Given: the access token really authorizes renewal before the revocation.
        useIssuer(issuer(variant));
        final var offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                CredentialSubjectFixtures.completeEmployeeProfile());
        final var initialEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final int batchSize = initialEntry.getIssuerMetadata().getBatchCredentialIssuance().getBatchSize();
        final var renewedEntry = initialEntry.duplicate();
        CredentialResponseAssert.assertThat(wallet.renewedCredentials(renewedEntry))
                .hasCode(200)
                .isResponseEncrypted();
        assertThat(initialEntry.getIssuedCredentials())
                .hasSize(batchSize);
        assertThat(renewedEntry.getIssuedCredentials())
                .hasSize(batchSize);

        final var renewalRequest = request()
                .withMethod("POST")
                .withPath("/renewal")
                .withBody(json("{\"management_id\":\"" + offer.getManagementId() + "\"}",
                        MatchType.ONLY_MATCHING_FIELDS));
        assertThat(mockServerClient.retrieveRecordedRequests(renewalRequest))
                .as("The same access token successfully renewed this family before revocation")
                .hasSize(1);
        final var initialCredentials = List.copyOf(initialEntry.getIssuedCredentials());
        final var renewedCredentials = List.copyOf(renewedEntry.getIssuedCredentials());
        final String statusPath = URI.create(getCurrentStatusList().getStatusRegistryUrl()).getPath();
        final URI statusUri = URI.create("http://%s:%d%s".formatted(
                mockServerContainer.getHost(), mockServerContainer.getServerPort(), statusPath));
        final String staleStatusList = restClient.get()
                .uri(statusUri)
                .retrieve()
                .body(String.class);
        assertThat(staleStatusList)
                .isNotBlank();
        final var staleExpectation = mockServerClient
                .when(request().withMethod("GET").withPath(statusPath),
                        Times.unlimited(), TimeToLive.unlimited(), 100)
                .respond(response()
                        .withStatusCode(200)
                        .withHeader("Content-Type", "application/statuslist+jwt")
                        .withBody(staleStatusList));

        try {
            // When: revocation is committed locally but its public snapshot remains stale.
            issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.REVOKED);
            final var revokedManagement = issuerManager.getCredentialById(offer.getManagementId());
            final var revokedReferences = credentialStatusReferences(offer.getManagementId());
            assertThat(revokedManagement.getStatus())
                    .isEqualTo(CredentialStatusType.REVOKED);
            assertThat(revokedManagement.getCredentialOffers())
                    .hasSize(2);
            assertThat(revokedReferences)
                    .hasSize(batchSize * 2);
            assertThat(restClient.get().uri(statusUri).retrieve().body(String.class))
                    .as("The simulated propagation gap is still present during the renewal attempt")
                    .isEqualTo(staleStatusList);
            awaitStableIssuerCallbacks();
            final var issuedCallbacksBefore = issuerCallbacks().stream()
                    .filter(callback -> callback.getEventType() == WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                    .filter(callback -> "ISSUED".equals(callback.getEvent()))
                    .toList();

            for (final var source : List.of(initialEntry, renewedEntry)) {
                final var rejectedEntry = source.duplicate();
                final var exception = assertThrows(HttpClientErrorException.class,
                        () -> wallet.renewedCredentials(rejectedEntry));

                // Then: fresh nonce, proofs and DPoP cannot bypass the current revoked state.
                ApiErrorAssert.assertThat(exception)
                        .hasStatus(400)
                        .hasError("credential_request_denied");
                assertThat(exception.getResponseHeaders())
                        .isNotNull();
                assertThat(exception.getResponseHeaders().getContentType())
                        .isNotNull()
                        .matches(type -> type.isCompatibleWith(MediaType.APPLICATION_JSON),
                                "Credential Error Responses are unencrypted JSON (OID4VCI 8.3.1.2)");
                assertThat(rejectedEntry.getIssuedCredentials())
                        .isEmpty();
                final var managementAfter = issuerManager.getCredentialById(offer.getManagementId());
                assertThat(managementAfter.getStatus())
                        .isEqualTo(CredentialStatusType.REVOKED);
                assertThat(managementAfter.getCredentialOffers())
                        .containsExactlyInAnyOrderElementsOf(revokedManagement.getCredentialOffers());
                assertThat(managementAfter.getRenewalRequestCount())
                        .isEqualTo(revokedManagement.getRenewalRequestCount());
                assertThat(managementAfter.getRenewalResponseCount())
                        .isEqualTo(revokedManagement.getRenewalResponseCount());
                assertThat(credentialStatusReferences(offer.getManagementId()))
                        .containsExactlyElementsOf(revokedReferences);
                assertThat(mockServerClient.retrieveRecordedRequests(renewalRequest))
                        .as("No revoked renewal reaches the Business Issuer, even if it would approve it")
                        .hasSize(1);
            }
            assertThat(initialEntry.getIssuedCredentials())
                    .containsExactlyElementsOf(initialCredentials);
            assertThat(renewedEntry.getIssuedCredentials())
                    .containsExactlyElementsOf(renewedCredentials);
            awaitStableIssuerCallbacks();
            assertThat(issuerCallbacks().stream()
                    .filter(callback -> callback.getEventType() == WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                    .filter(callback -> "ISSUED".equals(callback.getEvent()))
                    .toList())
                    .containsExactlyElementsOf(issuedCallbacksBefore);
        } finally {
            mockServerClient.clear(staleExpectation[0].getId());
        }
    }

    @ParameterizedTest(name = "[{index}] {0}, credential={1}, renewal allowed={2}")
    @MethodSource("renewalPolicies")
    @XrayTest(
            key = "EIDOMNI-1086",
            summary = "Credential Issuer applies the default, strict and experimental suspended-renewal policies",
            description = """
                    Given a renewable batch and the ENABLE_SUSPENDED_RENEWAL property unset, false, or true.
                    When the Wallet renews a SUSPENDED batch with a valid access token, fresh key proofs and DPoP.
                    Then the unset and false policies return HTTP 400 credential_request_denied without side effects,
                    while experimental Option 2 (true) returns one encrypted batch containing one VC per proof.
                    A VALID batch remains renewable under all three policies.
                    Accepted renewals preserve the original family and holder binding, use the Business Issuer data,
                    and do not reactivate a suspended family.
                    Spec: EIDOMNI-1086; OID4VCI 1.0 sections 8.2, 8.3.1.2 and 14.5;
                    Swiss issuance profile sections 14.5 and 14.6; Swiss VC profile section 7.1 (Status Types Values).
                    """)
    void credentialRenewal_whenStatusAndPolicyAreCombined_thenAppliesConfiguredPolicy(
            final IssuerVariant variant,
            final CredentialStatusType initialStatus,
            final boolean renewalAllowed) throws Exception {
        // Given: an unset property tests the product default, rather than injecting false for it.
        useIssuer(issuer(variant));
        final var offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                CredentialSubjectFixtures.completeEmployeeProfile());
        final var initialEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final var renewalEntry = initialEntry.duplicate();
        final int batchSize = initialEntry.getIssuerMetadata().getBatchCredentialIssuance().getBatchSize();
        assertThat(batchSize)
                .as("The Swiss issuance profile requires a metadata batch size of at least ten")
                .isGreaterThanOrEqualTo(10);
        assertThat(initialEntry.getIssuedCredentials())
                .hasSize(batchSize);
        if (initialStatus == CredentialStatusType.SUSPENDED) {
            issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.SUSPENDED);
        }
        final var managementBefore = issuerManager.getCredentialById(offer.getManagementId());
        final var referencesBefore = credentialStatusReferences(offer.getManagementId());
        assertThat(managementBefore.getStatus())
                .isEqualTo(initialStatus);
        final var renewalRequest = request()
                .withMethod("POST")
                .withPath("/renewal")
                .withBody(json("{\"management_id\":\"" + offer.getManagementId() + "\"}",
                        MatchType.ONLY_MATCHING_FIELDS));
        assertThat(mockServerClient.retrieveRecordedRequests(renewalRequest))
                .isEmpty();

        if (renewalAllowed) {
            // When
            final var credentialResponse = wallet.renewedCredentials(renewalEntry);

            // Then: a real encrypted, signed batch is issued, rather than only a successful HTTP response.
            CredentialResponseAssert.assertThat(credentialResponse)
                    .hasCode(200)
                    .hasNotTransactionId()
                    .isResponseEncrypted();
            assertThat(renewalEntry.getProofs())
                    .hasSize(batchSize);
            SdJwtBatchAssert.assertThat(renewalEntry.getIssuedCredentials())
                    .hasBatchSize(renewalEntry.getProofs().size())
                    .areUnique()
                    .haveUniqueHolderBindingKeys()
                    .haveUniqueStatusListIndexes()
                    .haveDisclosuresBoundToPayloadDigests()
                    .allHaveExactlyInAnyOrderDisclosures(CredentialSubjectFixtures.completeEmployeeProfile());
            assertThat(renewalEntry.getIssuedCredentials())
                    .doesNotContainAnyElementsOf(initialEntry.getIssuedCredentials());
            for (int index = 0; index < renewalEntry.getIssuedCredentials().size(); index++) {
                final var credential = SignedJWT.parse(renewalEntry.getIssuedCredentials().get(index).split("~")[0]);
                assertThat(credential.verify(new ECDSAVerifier((ECPublicKey) issuerConfig.getKeyPair().getPublic())))
                        .as("Renewed credential %s has a valid Credential Issuer signature", index)
                        .isTrue();
                final var claims = new ObjectMapper().readTree(credential.getPayload().toString());
                assertThat(JWK.parse(claims.path("cnf").path("jwk").toString()).computeThumbprint())
                        .as("Renewed credential %s is bound to the key from its proof", index)
                        .isEqualTo(renewalEntry.getHolderPublicKeys().get(index).computeThumbprint());
            }
            final var managementAfter = issuerManager.getCredentialById(offer.getManagementId());
            assertThat(managementAfter.getStatus())
                    .as("Renewal must not reactivate a suspended family")
                    .isEqualTo(initialStatus);
            assertThat(managementAfter.getCredentialOffers())
                    .hasSize(managementBefore.getCredentialOffers().size() + 1)
                    .containsAll(managementBefore.getCredentialOffers());
            assertThat(managementAfter.getRenewalRequestCount())
                    .isEqualTo(managementBefore.getRenewalRequestCount() + 1);
            assertThat(managementAfter.getRenewalResponseCount())
                    .isEqualTo(managementBefore.getRenewalResponseCount() + 1);
            assertThat(credentialStatusReferences(offer.getManagementId()))
                    .hasSize(referencesBefore.size() + renewalEntry.getProofs().size())
                    .containsAll(referencesBefore)
                    .doesNotHaveDuplicates();
            assertThat(mockServerClient.retrieveRecordedRequests(renewalRequest))
                    .hasSize(1);
        } else {
            // When
            final var exception = assertThrows(HttpClientErrorException.class,
                    () -> wallet.renewedCredentials(renewalEntry));

            // Then
            ApiErrorAssert.assertThat(exception)
                    .hasStatus(400)
                    .hasError("credential_request_denied");
            assertThat(exception.getResponseHeaders())
                    .isNotNull();
            assertThat(exception.getResponseHeaders().getContentType())
                    .isNotNull()
                    .matches(type -> type.isCompatibleWith(MediaType.APPLICATION_JSON),
                            "Credential Error Responses are unencrypted JSON (OID4VCI 8.3.1.2)");
            assertThat(renewalEntry.getIssuedCredentials())
                    .isEmpty();
            final var managementAfter = issuerManager.getCredentialById(offer.getManagementId());
            assertThat(managementAfter.getStatus())
                    .isEqualTo(CredentialStatusType.SUSPENDED);
            assertThat(managementAfter.getCredentialOffers())
                    .containsExactlyInAnyOrderElementsOf(managementBefore.getCredentialOffers());
            assertThat(managementAfter.getRenewalRequestCount())
                    .isEqualTo(managementBefore.getRenewalRequestCount());
            assertThat(managementAfter.getRenewalResponseCount())
                    .isEqualTo(managementBefore.getRenewalResponseCount());
            assertThat(credentialStatusReferences(offer.getManagementId()))
                    .containsExactlyElementsOf(referencesBefore);
            assertThat(mockServerClient.retrieveRecordedRequests(renewalRequest))
                    .as("A strict refusal must happen before the Business Issuer call")
                    .isEmpty();
        }
    }

    @ParameterizedTest(name = "unsupported status={0}")
    @ValueSource(strings = {"0x03", "UNKNOWN"})
    @XrayTest(key = "EIDOMNI-XXX",
            summary = "Business Issuer management API rejects unsupported statuses without changing the family",
            description = """
                    Given a suspended family with suspended renewal enabled.
                    When the Business Issuer requests an unsupported status, represented as 0x03 or UNKNOWN.
                    Then the management API answers HTTP 400 and leaves the management record unchanged.
                    Deviation: the requested status is outside the management API enumeration.
                    Spec: Issuer OpenAPI updateCredentialStatus and UpdateCredentialStatusRequestType.
                    """)
    void credentialManagement_whenBusinessIssuerRequestsUnsupportedStatus_thenRejectedWithoutSideEffects(
            final String unsupportedStatus) {
        // Given
        useIssuer(issuer(IssuerVariant.RENEWAL_PERMISSIVE_EXPERIMENTAL));
        final var offer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                CredentialSubjectFixtures.completeEmployeeProfile());
        wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.SUSPENDED);
        final var before = issuerManager.getCredentialById(offer.getManagementId());
        assertThat(before.getStatus())
                .isEqualTo(CredentialStatusType.SUSPENDED);

        // When: the raw value bypasses only the generated client's enum restriction.
        final var failure = assertThrows(HttpClientErrorException.class,
                () -> issuerManager.getCredentialApi().getApiClient().getRestClient()
                        .patch()
                        .uri(issuerConfig.getIssuerServiceUrl()
                                        + "/management/api/credentials/{id}/status?credentialStatus={status}",
                                offer.getManagementId(), unsupportedStatus)
                        .retrieve()
                        .toBodilessEntity());

        // Then
        ApiErrorAssert.assertThat(failure)
                .hasStatus(400);
        assertThat(issuerManager.getCredentialById(offer.getManagementId()))
                .usingRecursiveComparison()
                .isEqualTo(before);
    }

    private static Stream<Arguments> renewalPolicies() {
        return Stream.of(
                Arguments.of(IssuerVariant.RENEWAL_DEFAULT, CredentialStatusType.ISSUED, true),
                Arguments.of(IssuerVariant.RENEWAL_DEFAULT, CredentialStatusType.SUSPENDED, false),
                Arguments.of(IssuerVariant.RENEWAL_STRICT, CredentialStatusType.ISSUED, true),
                Arguments.of(IssuerVariant.RENEWAL_STRICT, CredentialStatusType.SUSPENDED, false),
                Arguments.of(IssuerVariant.RENEWAL_PERMISSIVE_EXPERIMENTAL, CredentialStatusType.ISSUED, true),
                Arguments.of(IssuerVariant.RENEWAL_PERMISSIVE_EXPERIMENTAL, CredentialStatusType.SUSPENDED, true));
    }

    /** Reads persisted references independently of the credential response, to detect partially created batches. */
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
