package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result;

import ch.admin.bj.swiyu.gen.verifier.model.CredentialEvaluation;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import lombok.experimental.UtilityClass;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.SoftAssertions.assertSoftly;

/** Assertions for a DCQL credential evaluation returned by the Business Verifier API. */
@UtilityClass
public class CredentialEvaluationAssert {

    public static void assertEvaluation(
            final ManagementResponse result,
            final String credentialQueryId,
            final boolean expectedValid,
            final int expectedStatus
    ) {
        assertThat(result.getCredentialEvaluation())
                .containsOnlyKeys(credentialQueryId);
        final List<CredentialEvaluation> evaluations = result.getCredentialEvaluation().get(credentialQueryId);
        assertThat(evaluations)
                .singleElement();
        final CredentialEvaluation evaluation = evaluations.getFirst();
        assertThat(evaluation.getCredentialStatus())
                .as("Credential status evaluation")
                .isNotNull();
        assertSoftly(softly -> {
            softly.assertThat(evaluation.getCredentialStatus().getValid())
                    .as("Credential status validity")
                    .isEqualTo(expectedValid);
            softly.assertThat(evaluation.getCredentialStatus().getStatus())
                    .as("Token Status List value")
                    .isEqualTo(expectedStatus);
        });
    }
}
