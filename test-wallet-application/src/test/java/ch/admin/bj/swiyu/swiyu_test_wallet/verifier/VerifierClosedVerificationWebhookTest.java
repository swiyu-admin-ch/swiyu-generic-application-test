package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.UseWallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact.SdJwtCredential;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockserver.matchers.MatchType;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.sql.SQLException;
import java.time.Duration;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.mock.MockServices.VERIFIER_CALLBACK_PATH;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.JsonBody.json;

/**
 * Once a verification is closed, a malicious Wallet must neither mutate its result nor enqueue more business callbacks.
 * Presentations and plaintext wallet errors use different verifier paths, so both need coverage after SUCCESS and FAILED.
 * Terminal-state immutability and the callback bound are project and ticket requirements, not OpenID webhook rules.
 */
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.COMPLETE)
@UseWallet(dpop = true, encryption = true, signedMetadata = true)
class VerifierClosedVerificationWebhookTest extends BaseTest {

    private static final int REPEATED_RESPONSES = 6;
    private static final Duration CALLBACK_OBSERVATION = Duration.ofSeconds(1);
    private static final Duration CALLBACK_TIMEOUT = Duration.ofSeconds(5);

    @ParameterizedTest(name = "presentations after {0}")
    @EnumSource(value = VerificationStatus.class, names = {"SUCCESS", "FAILED"})
    @XrayTest(
            key = "EIDOMNI-1411",
            summary = "Verifier rejects repeated presentations to a closed verification without further callbacks",
            description = """
                    Given a verification completed as SUCCESS or FAILED and its single business callback delivered.
                    When the Wallet posts six more encrypted Authorization Responses with a valid presentation to the same response URI.
                    Then every response returns HTTP 410, the complete stored result remains unchanged and no additional callback is delivered or queued.
                    Deviation: the Wallet continues submitting presentations after the verification is closed;
                    the FAILED setup uses a credential with a corrupted issuer signature.
                    Spec: OID4VP 1.0 §8.3 Encrypted Responses and §8.6 VP Token Validation; Swiss verification profile §8 Response.
                    HTTP 410, terminal-state immutability and the callback bound come from the verifier API and the ticket.
                    """)
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.EDGE_CASE)
    void presentation_whenWalletRepeatsResponsesAfterClosure_thenResultAndCallbackCountStayUnchanged(
            final VerificationStatus terminalState
    ) {
        // Given
        final OpenVerification open = openVerification();
        if (terminalState == VerificationStatus.SUCCESS) {
            wallet.respondToVerification(open.requestObject(), open.validPresentation());
        } else {
            final var rejection = assertThrows(HttpClientErrorException.class,
                    () -> wallet.respondToVerification(open.requestObject(), open.invalidPresentation()));
            ApiErrorAssert.assertThat(rejection)
                    .hasStatus(400)
                    .hasError("invalid_transaction_data");
        }
        final ManagementResponse closed = verifierManager.getVerificationById(open.verificationId());
        assertThat(closed.getState())
                .isEqualTo(terminalState);
        await()
                .atMost(CALLBACK_TIMEOUT)
                .untilAsserted(() -> assertThat(deliveredCallbacks(open.verificationId()))
                        .isEqualTo(1));

        // When
        for (int response = 0; response < REPEATED_RESPONSES; response++) {
            final var rejection = assertThrows(HttpClientErrorException.class,
                    () -> wallet.respondToVerification(open.requestObject(), open.validPresentation()));
            ApiErrorAssert.assertThat(rejection)
                    .hasStatus(410);
        }

        // Then
        assertThat(verifierManager.getVerificationById(open.verificationId()))
                .usingRecursiveComparison()
                .isEqualTo(closed);
        await()
                .during(CALLBACK_OBSERVATION)
                .atMost(CALLBACK_TIMEOUT)
                .untilAsserted(() -> {
                    assertThat(deliveredCallbacks(open.verificationId()))
                            .as("Delivered callbacks after presentations to a %s verification", terminalState)
                            .isEqualTo(1);
                    assertThat(queuedCallbacks(open.verificationId()))
                            .isZero();
                });
    }

    @ParameterizedTest(name = "wallet errors after {0}")
    @EnumSource(value = VerificationStatus.class, names = {"SUCCESS", "FAILED"})
    @XrayTest(
            key = "EIDOMNI-1412",
            summary = "Verifier rejects repeated wallet errors to a closed verification without further callbacks",
            description = """
                    Given a verification completed by a valid presentation as SUCCESS or by an access_denied response as FAILED, with its single callback delivered.
                    When the Wallet posts six access_denied error responses to the same response URI.
                    Then every response returns HTTP 410, the complete stored result remains unchanged and no additional callback is delivered or queued.
                    Deviation: the Wallet continues answering a verification that is already closed.
                    Spec: OID4VP 1.0 §8.5 Error Response; Swiss verification profile §8.5 Error Response says errors SHOULD be never encrypted.
                    HTTP 410, terminal-state immutability and the callback bound come from the verifier API and the ticket.
                    """)
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.EDGE_CASE)
    void walletError_whenWalletRepeatsResponsesAfterClosure_thenResultAndCallbackCountStayUnchanged(
            final VerificationStatus terminalState
    ) {
        // Given
        final OpenVerification open = openVerification();
        if (terminalState == VerificationStatus.SUCCESS) {
            wallet.respondToVerification(open.requestObject(), open.validPresentation());
        } else {
            wallet.respondToVerificationWithError(open.requestObject(), "access_denied", "user declined");
        }
        final ManagementResponse closed = verifierManager.getVerificationById(open.verificationId());
        assertThat(closed.getState())
                .isEqualTo(terminalState);
        await()
                .atMost(CALLBACK_TIMEOUT)
                .untilAsserted(() -> assertThat(deliveredCallbacks(open.verificationId()))
                        .isEqualTo(1));

        // When
        for (int response = 0; response < REPEATED_RESPONSES; response++) {
            final var rejection = assertThrows(HttpClientErrorException.class,
                    () -> wallet.respondToVerificationWithError(open.requestObject(), "access_denied", "user declined"));
            ApiErrorAssert.assertThat(rejection)
                    .hasStatus(410);
        }

        // Then
        assertThat(verifierManager.getVerificationById(open.verificationId()))
                .usingRecursiveComparison()
                .isEqualTo(closed);
        await()
                .during(CALLBACK_OBSERVATION)
                .atMost(CALLBACK_TIMEOUT)
                .untilAsserted(() -> {
                    assertThat(deliveredCallbacks(open.verificationId()))
                            .as("Delivered callbacks after wallet errors to a %s verification", terminalState)
                            .isEqualTo(1);
                    assertThat(queuedCallbacks(open.verificationId()))
                            .isZero();
                });
    }

    private OpenVerification openVerification() {
        final var offer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final WalletBatchEntry entry = wallet.collectOffer(toUri(offer.getOfferDeeplink()), 1);
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withDCQL()
                .encrypted()
                .createManagementResponse();
        final RequestObject requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String validPresentation = entry.createPresentationForSdJwtIndex(0, requestObject);
        entry.replaceIssuedCredential(0, SdJwtCredential.parse(entry.getVerifiableCredential(0))
                .withCorruptedIssuerSignature()
                .serialize());
        final String invalidPresentation = entry.createPresentationForSdJwtIndex(0, requestObject);
        return new OpenVerification(verification.getId(), requestObject, validPresentation, invalidPresentation);
    }

    private int deliveredCallbacks(final UUID verificationId) {
        return mockServerClient.retrieveRecordedRequests(request()
                .withMethod("POST")
                .withPath(VERIFIER_CALLBACK_PATH)
                .withBody(json("""
                        {"verification_id":"%s"}
                        """.formatted(verificationId), MatchType.ONLY_MATCHING_FIELDS)))
                .length;
    }

    private long queuedCallbacks(final UUID verificationId) throws SQLException {
        final String sql = "SELECT count(*) FROM %s.callback_event WHERE verification_id = ?"
                .formatted(verifierImageConfig.getDbSchema());
        try (var query = connection.prepareStatement(sql)) {
            query.setObject(1, verificationId);
            try (var result = query.executeQuery()) {
                result.next();
                return result.getLong(1);
            }
        }
    }

    private record OpenVerification(
            UUID verificationId,
            RequestObject requestObject,
            String validPresentation,
            String invalidPresentation
    ) {
    }
}
