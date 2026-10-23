package ch.admin.bj.swiyu.swiyu_test_wallet.fixture;

import lombok.experimental.UtilityClass;

@UtilityClass
// Test support type; its name does not identify a JUnit test class.
@SuppressWarnings("PMD.TestClassWithoutTestCases")
public class TestConstants {
    public static final String ISSUER_URL = "http://default-issuer-url.admin.ch";
    public static final String VERIFIER_URL = "http://default-verifier-url.admin.ch";
    public static final int UNIVERSITY_EXAMPLE_BATCH_SIZE = 10;
}
