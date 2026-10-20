package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationErrorResponseCode;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact.KeyBindingJwt;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.credential.HeldCredential;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto.Sha256Base64Url;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.time.Duration;
import java.time.Instant;
import java.util.function.BiFunction;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierKeyBindingValidationE2ETest extends BaseTest {

    private static final Duration CLOCK_SKEW_BEYOND_TOLERANCE = Duration.ofHours(1);

    @ParameterizedTest(name = "[{index}] reject {0}")
    @EnumSource(KeyBindingDeviation.class)
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Verifier rejects a Key Binding JWT that is not bound to this request and presentation",
            description = """
                    Given a holder-bound credential and a pending DCQL verification.
                    When the wallet presents the credential with a Key Binding JWT signed by the correct holder key
                    but with exactly one deviation: the nonce of another request, the audience of another verifier,
                    an sd_hash over another presentation, or an iat outside the accepted window.
                    Then the Verifier returns HTTP 400, persists the verification as FAILED with the specific error,
                    and emits exactly one callback.
                    Deviation: One Key Binding JWT claim differs from the request, presentation or freshness policy.
                    Spec: RFC 9901 §4.3 and §7.3; OID4VP 1.0 Appendix B.3.6 and §14.1.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1B)
    @Tag(ReportingTags.EDGE_CASE)
    void presentation_whenKeyBindingJwtDeviates_thenFailedWithStoredErrorAndOneCallback(
            final KeyBindingDeviation deviation
    ) {
        // Given
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
        );
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final HeldCredential heldCredential = batchEntry.heldCredential(0);

        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withDCQL()
                .createManagementResponse();
        final RequestObject requestObject = wallet.getVerificationRequestObject(
                verification.getVerificationDeeplink()
        );
        final KeyBindingJwt.Builder keyBinding = KeyBindingJwt.forPresentation(
                        heldCredential.sdJwt(),
                        requestObject.getClientId(),
                        requestObject.getNonce()
                )
                .signedWith(heldCredential.holderKey());
        final String presentation = heldCredential.sdJwt()
                + deviation.apply(keyBinding, heldCredential).build();
        final int callbacksBefore = awaitStableVerifierCallbacks();

        // When
        final HttpClientErrorException exception = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.respondToVerification(requestObject, presentation)
        );

        // Then
        ApiErrorAssert.assertThat(exception)
                .hasStatus(400)
                .hasError("invalid_transaction_data")
                .hasDetail(deviation.errorCode().getValue())
                .hasErrorCode(deviation.errorCode().getValue());

        final ManagementResponse failedVerification = verifierManager.verifyState(
                verification.getId(),
                VerificationStatus.FAILED
        );
        assertThat(failedVerification.getWalletResponse().getErrorCode())
                .isEqualTo(deviation.errorCode());
        assertThat(failedVerification.getWalletResponse().getCredentialSubjectData())
                .as("A presentation without a valid key binding must not expose credential claims")
                .isNullOrEmpty();
        awaitOneVerifierCallback(callbacksBefore);
        assertThat(awaitStableVerifierCallbacks())
                .isEqualTo(callbacksBefore + 1);
    }

    private enum KeyBindingDeviation {
        /** Deviation: the nonce of another Authorization Request, i.e. a presentation replayed into this one. */
        NONCE_OF_ANOTHER_REQUEST(
                VerificationErrorResponseCode.HOLDER_BINDING_MISMATCH,
                (keyBinding, held) -> keyBinding.withNonce("nonce-of-another-request")
        ),
        /** Deviation: aud names another Verifier than the one that asked. */
        AUDIENCE_OF_ANOTHER_VERIFIER(
                VerificationErrorResponseCode.HOLDER_BINDING_MISMATCH,
                (keyBinding, held) -> keyBinding.withAudience("decentralized_identifier:did:tdw:example:other-verifier")
        ),
        /** Deviation: sd_hash covers another presentation, so the presented Disclosures are not the ones the holder signed. */
        SD_HASH_OF_ANOTHER_PRESENTATION(
                VerificationErrorResponseCode.HOLDER_BINDING_MISMATCH,
                (keyBinding, held) -> keyBinding.withSdHash(Sha256Base64Url.ofUsAscii(held.sdJwt() + "another~"))
        ),
        /** Deviation: iat is far in the past, so the proof is not fresh. */
        ISSUED_AT_IN_THE_PAST(
                VerificationErrorResponseCode.HOLDER_BINDING_MISMATCH,
                (keyBinding, held) -> keyBinding.withIssuedAt(Instant.now().minus(CLOCK_SKEW_BEYOND_TOLERANCE))
        ),
        /** Deviation: iat is far in the future. */
        ISSUED_AT_IN_THE_FUTURE(
                VerificationErrorResponseCode.HOLDER_BINDING_MISMATCH,
                (keyBinding, held) -> keyBinding.withIssuedAt(Instant.now().plus(CLOCK_SKEW_BEYOND_TOLERANCE))
        );

        private final VerificationErrorResponseCode expectedError;
        private final BiFunction<KeyBindingJwt.Builder, HeldCredential, KeyBindingJwt.Builder> deviation;

        KeyBindingDeviation(
                final VerificationErrorResponseCode errorCode,
                final BiFunction<KeyBindingJwt.Builder, HeldCredential, KeyBindingJwt.Builder> deviation
        ) {
            this.expectedError = errorCode;
            this.deviation = deviation;
        }

        VerificationErrorResponseCode errorCode() {
            return expectedError;
        }

        KeyBindingJwt.Builder apply(final KeyBindingJwt.Builder keyBinding, final HeldCredential heldCredential) {
            return deviation.apply(keyBinding, heldCredential);
        }
    }
}
