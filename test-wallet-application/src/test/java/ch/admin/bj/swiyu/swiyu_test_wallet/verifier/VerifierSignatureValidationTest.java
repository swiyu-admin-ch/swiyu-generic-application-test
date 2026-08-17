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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierSignatureValidationTest extends BaseTest {

    @AfterEach
    void restoreValidStatusListSignature() {
        mockServerClientConfig.disableCorruptStatusListSignature();
    }

    @ParameterizedTest(name = "[{index}] reject {0}")
    @EnumSource(SignatureFailure.class)
    @XrayTest(
            key = "EIDOMNI-1243",
            summary = "Signature verification errors close the verification as failed",
            description = """
                    Given a valid issuer-wallet-verifier flow whose credential or status-list signature is deliberately corrupted.
                    When the wallet submits a holder-bound presentation to the Verifier.
                    Then the Verifier returns HTTP 400, persists the verification as FAILED with the specific error,
                    and emits exactly one callback instead of leaving the verification PENDING.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1B)
    @Tag(ReportingTags.EDGE_CASE)
    void verification_whenSignatureIsInvalid_thenFailedWithStoredErrorAndOneCallback(
            final SignatureFailure signatureFailure
    ) {
        // Given
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
        );
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        applySignatureFailure(signatureFailure, batchEntry);

        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withDCQL()
                .createManagementResponse();
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

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
                .hasDetail(signatureFailure.errorCode().getValue())
                .hasErrorCode(signatureFailure.errorCode().getValue());

        final ManagementResponse failedVerification = verifierManager.verifyState(
                verification.getId(),
                VerificationStatus.FAILED
        );
        assertThat(failedVerification.getWalletResponse())
                .as("The signature validation error must be persisted")
                .isNotNull();
        assertThat(failedVerification.getWalletResponse().getErrorCode())
                .isEqualTo(signatureFailure.errorCode());
        assertThat(failedVerification.getWalletResponse().getErrorDescription())
                .isNotBlank();
        awaitOneVerifierCallback(callbacksBefore);
    }

    private void applySignatureFailure(
            final SignatureFailure signatureFailure,
            final WalletBatchEntry batchEntry
    ) {
        switch (signatureFailure) {
            case CREDENTIAL_SIGNATURE -> replaceCredentialWithCorruptedSignature(batchEntry);
            case STATUS_LIST_SIGNATURE -> mockServerClientConfig.enableCorruptStatusListSignature();
        }
    }

    private void replaceCredentialWithCorruptedSignature(final WalletBatchEntry batchEntry) {
        final String issuedCredential = batchEntry.getVerifiableCredential(0);
        final int disclosureSeparator = issuedCredential.indexOf('~');
        assertThat(disclosureSeparator)
                .as("The issued SD-JWT must contain disclosures")
                .isPositive();

        final String corruptedIssuerJwt = corruptJwtSignature(
                issuedCredential.substring(0, disclosureSeparator)
        );
        batchEntry.clearIssuedCredentials();
        batchEntry.addIssuedCredential(
                corruptedIssuerJwt + issuedCredential.substring(disclosureSeparator)
        );
    }

    private String corruptJwtSignature(final String jwt) {
        final String[] parts = jwt.split("\\.", -1);
        assertThat(parts)
                .as("The issuer credential must be a compact JWS")
                .hasSize(3);
        assertThat(parts[2])
                .as("The issuer credential JWS must have a signature")
                .isNotEmpty();

        final char replacement = parts[2].charAt(0) == 'A' ? 'B' : 'A';
        parts[2] = replacement + parts[2].substring(1);
        return String.join(".", parts);
    }

    private enum SignatureFailure {
        CREDENTIAL_SIGNATURE(VerificationErrorResponseCode.MALFORMED_CREDENTIAL),
        STATUS_LIST_SIGNATURE(VerificationErrorResponseCode.UNRESOLVABLE_STATUS_LIST);

        private final VerificationErrorResponseCode errorCode;

        SignatureFailure(final VerificationErrorResponseCode errorCode) {
            this.errorCode = errorCode;
        }

        VerificationErrorResponseCode errorCode() {
            return errorCode;
        }
    }
}
