package ch.admin.bj.swiyu.swiyu_test_wallet.test_support;

import java.io.Serial;

// Test support type; its name does not identify a JUnit test class.
@SuppressWarnings("PMD.TestClassWithoutTestCases")
public class TestSupportException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    public TestSupportException(final String message) {
        super(message);
    }

    public TestSupportException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
