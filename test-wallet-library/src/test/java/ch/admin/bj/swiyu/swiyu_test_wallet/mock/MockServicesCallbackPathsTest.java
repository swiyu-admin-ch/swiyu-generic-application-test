package ch.admin.bj.swiyu.swiyu_test_wallet.mock;

import org.junit.jupiter.api.Test;

import static ch.admin.bj.swiyu.swiyu_test_wallet.mock.MockServices.ISSUER_CALLBACK_PATH;
import static ch.admin.bj.swiyu.swiyu_test_wallet.mock.MockServices.VERIFIER_CALLBACK_PATH;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards the test oracle for webhook callbacks. The Issuer and the Verifier post to the same MockServer, and the tests
 * count the requests received on each path. If both used the same path, a Verifier callback would be counted as an
 * Issuer callback (and the other way round), and callback assertions could pass or fail for the wrong component.
 */
class MockServicesCallbackPathsTest {

    @Test
    void issuerAndVerifierCallbacksUseDistinctMockServerPaths() {
        assertThat(VERIFIER_CALLBACK_PATH)
                .isNotEqualTo(ISSUER_CALLBACK_PATH);
    }

    @Test
    void callbackPathsAreAbsoluteAndNotNestedInEachOther() {
        assertThat(ISSUER_CALLBACK_PATH)
                .startsWith("/")
                .doesNotStartWith(VERIFIER_CALLBACK_PATH);
        assertThat(VERIFIER_CALLBACK_PATH)
                .startsWith("/")
                .doesNotStartWith(ISSUER_CALLBACK_PATH);
    }
}
