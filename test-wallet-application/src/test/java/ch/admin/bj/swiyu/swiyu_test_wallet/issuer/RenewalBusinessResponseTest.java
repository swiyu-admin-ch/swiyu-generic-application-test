package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_response.CredentialResponseAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.UseWallet;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockserver.matchers.MatchType;
import org.mockserver.matchers.TimeToLive;
import org.mockserver.matchers.Times;
import org.mockserver.mock.Expectation;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.mockserver.model.JsonBody.json;

/** Business Issuer response contracts exercised through real, encrypted Wallet renewal requests. */
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.RENEWAL_PERMISSIVE_EXPERIMENTAL)
@UseWallet(dpop = true, encryption = true, signedMetadata = true)
@Tag(ReportingTags.UCI_I1)
@Tag(ReportingTags.EDGE_CASE)
class RenewalBusinessResponseTest extends BaseTest {

    @ParameterizedTest(name = "[{index}] suspended renewal, fractional digits={0}")
    @ValueSource(ints = {0, 3, 6, 9})
    @XrayTest(key = "EIDOMNI-1086",
            summary = "Credential Issuer accepts valid date-time precision in the renewal response",
            description = """
                    Given a suspended family with experimental suspended renewal enabled.
                    When the Business Issuer returns credential_valid_from and credential_valid_until
                    with zero, three, six or nine fractional second digits.
                    Then the Wallet receives a complete encrypted batch and the family remains SUSPENDED.
                    Spec: Issuer OpenAPI RenewalResponse date-time / XMLSchema dateTimeStamp contract;
                    OID4VCI 1.0 section 8.3; Swiss issuance profile sections 8.3 and 14.6.
                    """)
    void credentialRenewal_whenBusinessIssuerUsesValidDateTimePrecision_thenIssuesBatch(final int fractionalDigits) {
        // Given
        useIssuer(issuer(IssuerVariant.RENEWAL_PERMISSIVE_EXPERIMENTAL));
        final var offer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                CredentialSubjectFixtures.completeEmployeeProfile());
        final var initialEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final var renewalEntry = initialEntry.duplicate();
        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.SUSPENDED);
        final var expectation = renewalResponse(offer.getManagementId(), fractionalDigits);
        try {
            // When
            final var response = wallet.renewedCredentials(renewalEntry);

            // Then
            CredentialResponseAssert.assertThat(response)
                    .hasCode(200)
                    .isResponseEncrypted();
            assertThat(renewalEntry.getIssuedCredentials())
                    .hasSize(renewalEntry.getProofs().size());
            assertThat(issuerManager.getCredentialById(offer.getManagementId()).getStatus())
                    .isEqualTo(CredentialStatusType.SUSPENDED);
        } finally {
            mockServerClient.clear(expectation[0].getId());
        }
    }

    private Expectation[] renewalResponse(final UUID managementId, final int fractionalDigits) {
        final long nanos = switch (fractionalDigits) {
            case 0 -> 0;
            case 3 -> 123_000_000;
            case 6 -> 123_456_000;
            case 9 -> 123_456_789;
            default -> throw new IllegalArgumentException("Unsupported precision: " + fractionalDigits);
        };
        final Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS).plusNanos(nanos);
        final String body = new ObjectMapper().writeValueAsString(Map.of(
                "metadata_credential_supported_id", List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT),
                "credential_subject_data", CredentialSubjectFixtures.completeEmployeeProfile(),
                "credential_metadata", Map.of("deferred", false),
                "credential_valid_from", now.minus(1, ChronoUnit.DAYS).toString(),
                "credential_valid_until", now.plus(7, ChronoUnit.DAYS).toString(),
                "status_lists", List.of(getCurrentStatusList().getStatusRegistryUrl())));
        return mockServerClient.when(request()
                        .withMethod("POST")
                        .withPath("/renewal")
                        .withBody(json("{\"management_id\":\"" + managementId + "\"}",
                                MatchType.ONLY_MATCHING_FIELDS)),
                        Times.exactly(1), TimeToLive.unlimited(), 100)
                .respond(response().withStatusCode(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(body));
    }
}
