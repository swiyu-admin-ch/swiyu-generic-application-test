package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_status;

import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.StatusResponse;
import org.assertj.core.api.Assertions;

/** Fluent assertions for the status returned by the Issuer management API. */
public final class CredentialStatusAssert {

    private final StatusResponse currentStatus;

    private CredentialStatusAssert(final StatusResponse currentStatus) {
        this.currentStatus = currentStatus;
    }

    /**
     * Starts an assertion for a credential status response.
     *
     * @param currentStatus response returned by the Issuer management API
     * @return fluent credential status assertion
     */
    public static CredentialStatusAssert assertThat(final StatusResponse currentStatus) {
        Assertions.assertThat(currentStatus)
                .as("Credential status response")
                .isNotNull();
        return new CredentialStatusAssert(currentStatus);
    }

    /**
     * Verifies the current credential lifecycle status.
     *
     * @param expectedStatus expected Issuer management status
     * @return this assertion for further checks
     */
    public CredentialStatusAssert hasStatus(final CredentialStatusType expectedStatus) {
        Assertions.assertThat(currentStatus.getStatus())
                .as("Credential status")
                .isEqualTo(expectedStatus);
        return this;
    }
}
