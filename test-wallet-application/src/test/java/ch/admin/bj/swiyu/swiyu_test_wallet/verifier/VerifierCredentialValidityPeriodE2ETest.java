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
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact.SdJwtCredential;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierCredentialValidityPeriodE2ETest extends BaseTest {

    private static final Duration OUTSIDE_VALIDITY = Duration.ofHours(1);

    @ParameterizedTest(name = "[{index}] reject {0}")
    @EnumSource(ValidityPeriod.class)
    @XrayTest(
            key = "EIDOMNI-1468",
            summary = "Verifier rejects a credential outside its validity period",
            description = """
                    Given a holder-bound credential signed again by the Credential Issuer's own key with either an exp
                    in the past or an nbf in the future, and a pending DCQL verification.
                    When the wallet presents the credential with a valid Key Binding JWT.
                    Then the Verifier returns HTTP 400, persists the verification as FAILED with malformed_credential,
                    and emits exactly one callback.
                    Deviation: The Wallet presents a credential outside its signed validity period.
                    Spec: SD-JWT VC §3.2.2.2; RFC 7519 §4.1.4 and §4.1.5; Swiss VC profile.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1B)
    @Tag(ReportingTags.EDGE_CASE)
    void presentation_whenCredentialIsOutsideValidityPeriod_thenFailedWithStoredErrorAndOneCallback(
            final ValidityPeriod validityPeriod
    ) {
        // Given
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
        );
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        batchEntry.replaceIssuedCredential(0, validityPeriod.resign(batchEntry.getVerifiableCredential(0), issuerConfig.getKeyPair()));

        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withDCQL()
                .createManagementResponse();
        final RequestObject requestObject = wallet.getVerificationRequestObject(
                verification.getVerificationDeeplink()
        );
        final String presentation = batchEntry.createPresentationForSdJwtIndex(0, requestObject);
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
                .hasDetail(VerificationErrorResponseCode.MALFORMED_CREDENTIAL.getValue())
                .hasErrorCode(VerificationErrorResponseCode.MALFORMED_CREDENTIAL.getValue())
                .hasErrorDescription("SD-JWT claims are not valid");

        final ManagementResponse failedVerification = verifierManager.verifyState(
                verification.getId(),
                VerificationStatus.FAILED
        );
        assertThat(failedVerification.getWalletResponse().getErrorCode())
                .isEqualTo(VerificationErrorResponseCode.MALFORMED_CREDENTIAL);
        awaitOneVerifierCallback(callbacksBefore);
        assertThat(awaitStableVerifierCallbacks())
                .isEqualTo(callbacksBefore + 1);
    }

    private enum ValidityPeriod {
        /** Deviation: exp is in the past; everything else, including the status claim, is as issued. */
        EXPIRED {
            @Override
            SdJwtCredential.Resign apply(final SdJwtCredential.Resign resign) {
                return resign.expiresAt(Instant.now().minus(OUTSIDE_VALIDITY));
            }
        },
        /** Deviation: nbf is in the future; everything else, including the status claim, is as issued. */
        NOT_YET_VALID {
            @Override
            SdJwtCredential.Resign apply(final SdJwtCredential.Resign resign) {
                return resign.notBefore(Instant.now().plus(OUTSIDE_VALIDITY));
            }
        };

        abstract SdJwtCredential.Resign apply(SdJwtCredential.Resign resign);

        String resign(final String credential, final KeyPair issuerKey) {
            return apply(SdJwtCredential.parse(credential).resign().signedWith(issuerKey)).build().serialize();
        }
    }
}
