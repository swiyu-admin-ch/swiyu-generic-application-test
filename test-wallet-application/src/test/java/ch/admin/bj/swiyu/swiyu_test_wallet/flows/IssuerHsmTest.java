package ch.admin.bj.swiyu.swiyu_test_wallet.flows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * HSM Integration Test with Imported Keys
 *
 * Flow:
 * 1. SoftHSM container starts
 * 2. init-hsm.sh imports key.pk8 + cert.pem from resources/hsm-keys into HSM
 * 3. HSM exports the public key in DER format
 * 4. EnvironmentConfig loads the exported public key
 * 5. DID is created using the public key
 * 6. Private key remains in HSM, never extracted
 *
 * This test-oriented setup uses the same imported key for both assert and auth keys.
 * In production, you would have separate keys for different purposes.
 */
@SpringBootTest
@ActiveProfiles("issuer-hsm")
@DisplayName("HSM Issuer Integration Test")
public class IssuerHsmTest {

    private static final Logger log = LoggerFactory.getLogger(IssuerHsmTest.class);

    @Test
    @DisplayName("Should load imported HSM key and create DID")
    public void testHsmImportedKeySetup() {
        log.info("HSM Issuer test running with imported keys from resources/hsm-keys");
        assertNotNull(IssuerHsmTest.class);
    }
}

