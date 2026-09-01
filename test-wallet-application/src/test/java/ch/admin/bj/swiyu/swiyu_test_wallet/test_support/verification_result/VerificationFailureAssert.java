package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result;

import ch.admin.bj.swiyu.gen.verifier.model.CredentialEvaluation;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import org.springframework.web.client.HttpClientErrorException;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies negative OID4VP results across the legacy and transparent-evaluation contracts.
 *
 * <p>Legacy verifier images return an HTTP 400 response for an invalid credential. Newer verifier
 * images accept the wallet submission, persist the reason in {@code credential_evaluation}, and
 * expose {@link VerificationStatus#FAILED} through the management API. Both contracts must preserve
 * the same security invariant: the invalid presentation never reaches {@code SUCCESS}.</p>
 */
public final class VerificationFailureAssert {

    private VerificationFailureAssert() {
    }

    /**
     * Submits a wallet response and validates either the legacy HTTP error or the transparent
     * credential evaluation, followed by the terminal failed state.
     *
     * @param submission the wallet-facing OID4VP submission
     * @param verifierManager verifier management API client
     * @param verificationId identifier of the verification process
     * @param legacyErrorAssertions assertions for verifier versions returning HTTP 400
     * @param evaluationAssertions assertions for verifier versions returning a credential evaluation
     */
    public static void assertRejected(
            final Runnable submission,
            final VerifierManager verifierManager,
            final UUID verificationId,
            final Consumer<HttpClientErrorException> legacyErrorAssertions,
            final Consumer<CredentialEvaluation> evaluationAssertions
    ) {
        final HttpClientErrorException legacyError = submit(submission);
        final ManagementResponse result = verifierManager.verifyState(verificationId, VerificationStatus.FAILED);

        if (legacyError != null) {
            assertThat(result.getCredentialEvaluation())
                    .as("Legacy HTTP failures must not contain transparent credential evaluations")
                    .isNullOrEmpty();
            legacyErrorAssertions.accept(legacyError);
            return;
        }

        final Map<String, List<CredentialEvaluation>> credentialEvaluations = result.getCredentialEvaluation();
        assertThat(credentialEvaluations)
                .as("A failed submission without an HTTP error must expose credential evaluations")
                .isNotNull()
                .hasSize(1);

        final List<CredentialEvaluation> evaluations = credentialEvaluations.values()
                .stream()
                .flatMap(List::stream)
                .toList();

        assertThat(evaluations)
                .as("Exactly one presented credential must be evaluated")
                .singleElement()
                .satisfies(evaluationAssertions);
    }

    /**
     * Verifies that a credential evaluation reports the expected token status-list state.
     */
    public static void assertCredentialStatus(
            final CredentialEvaluation evaluation,
            final CredentialStatusState expectedStatus
    ) {
        assertThat(evaluation.getCredentialStatus())
                .as("The credential status evaluation must be present")
                .isNotNull()
                .satisfies(status -> {
                    assertThat(status.getValid()).isFalse();
                    assertThat(status.getStatus()).isEqualTo(expectedStatus.getCode());
                });
    }

    /**
     * Verifies that issuer trust evaluation was performed and rejected the credential issuer.
     */
    public static void assertIssuerUntrusted(final CredentialEvaluation evaluation) {
        assertThat(evaluation.getTrustMarkers())
                .as("The issuer trust evaluation must be present")
                .isNotNull()
                .extracting(marker -> marker.getIsTrusted())
                .isEqualTo(false);
    }

    private static HttpClientErrorException submit(final Runnable submission) {
        try {
            submission.run();
            return null;
        } catch (final HttpClientErrorException exception) {
            return exception;
        }
    }

    /**
     * Credential status-list values exposed by the verifier evaluation API.
     */
    public enum CredentialStatusState {
        REVOKED(1),
        SUSPENDED(2);

        private final int code;

        CredentialStatusState(final int code) {
            this.code = code;
        }

        private int getCode() {
            return code;
        }
    }
}
