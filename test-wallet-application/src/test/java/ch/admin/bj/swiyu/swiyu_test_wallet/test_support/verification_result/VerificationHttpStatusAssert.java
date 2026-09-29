package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result;

import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import lombok.experimental.UtilityClass;
import org.springframework.http.ResponseEntity;

import java.util.UUID;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Keeps Wallet API and Business Verifier management API status assertions independent.
 */
@UtilityClass
public class VerificationHttpStatusAssert {

    public static ManagementResponse assertWalletAndManagementRespondOk(
            final Supplier<ResponseEntity<String>> walletSubmission,
            final VerifierManager verifierManager,
            final UUID verificationId
    ) {
        final ResponseEntity<String> walletResponse = walletSubmission.get();
        assertThat(walletResponse.getStatusCode().value())
                .as("Wallet OID4VP HTTP status")
                .isEqualTo(200);

        final ResponseEntity<ManagementResponse> managementResponse =
                verifierManager.getVerificationByIdWithHttpInfo(verificationId);
        assertThat(managementResponse.getStatusCode().value())
                .as("Business Verifier management HTTP status")
                .isEqualTo(200);
        assertThat(managementResponse.getBody())
                .as("Business Verifier management response body")
                .isNotNull();
        return managementResponse.getBody();
    }
}
