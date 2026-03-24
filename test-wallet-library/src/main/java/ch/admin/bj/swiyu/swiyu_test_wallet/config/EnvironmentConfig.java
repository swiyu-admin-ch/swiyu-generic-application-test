package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil;
import lombok.experimental.UtilityClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.security.KeyPair;
import java.security.Signature;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.DidLogUtil.createDidLog;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.DidLogUtil.getDidFromDidLog;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil.createJWKFromKeyPair;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil.generateEC256KeyPair;

@UtilityClass
public class EnvironmentConfig {

    private static final Logger log = LoggerFactory.getLogger(EnvironmentConfig.class);

    public static IssuerConfig createIssueraConfig(URI identifierRegistryUrl) {
        return createIssueraConfig(identifierRegistryUrl, false, null);
    }

    public static IssuerConfig createIssueraConfig(URI identifierRegistryUrl, boolean enableHsm, String hsmTokenDir) {
        KeyPair assertKeys;
        KeyPair authKeys;
        boolean isHsmMode = false;

        if (enableHsm && hsmTokenDir != null) {
            KeyPair assertImportedKeyPair = HsmExportedKeyLoader.loadHsmExportedKeyPair(hsmTokenDir, "assert");
            KeyPair authImportedKeyPair = HsmExportedKeyLoader.loadHsmExportedKeyPair(hsmTokenDir, "auth");

            if (!validateKeyPair(assertImportedKeyPair)) {
                throw new RuntimeException("Invalid ASSERT key pair: public/private mismatch");
            }
            /*
            if (!validateKeyPair(authImportedKeyPair)) {
                throw new RuntimeException("Invalid AUTH key pair: public/private mismatch");
            }

             */

            assertKeys = assertImportedKeyPair;
            authKeys = assertImportedKeyPair;
        } else {
            assertKeys = generateEC256KeyPair();
            authKeys = generateEC256KeyPair();
        }

        var assertJwk = createJWKFromKeyPair(assertKeys);
        var authJwk = createJWKFromKeyPair(authKeys);

        var didLog = createDidLog(authJwk, assertJwk, identifierRegistryUrl);
        var issuerDid = getDidFromDidLog(didLog);

        String assertKeyPem = KeyUtil.getPrivateKeyPem(assertKeys);
        String authKeyPem = KeyUtil.getPrivateKeyPem(authKeys);

        return IssuerConfig.builder()
                .swiyuPartnerId(UUID.randomUUID().toString())
                .issuerRegistryEntry(identifierRegistryUrl.toString())
                .issuerDid(issuerDid)
                .issuerDidLog(didLog)
                .mockServerUri(String.format("http://%s", MockServerClientConfig.MOCKSERVER_HOST))
                .issuerAssertKeyId(issuerDid + "#assert-key-01")
                .issuerAuthKeyId(issuerDid + "#assert-key-01")
                .issuerAssertKeyPemString(assertKeyPem)
                .issuerAuthKeyPemString(authKeyPem)
                .keyPair(assertKeys)
                .build();
    }

    /**
     * Wait for the HSM exported key files to be available.
     * This is needed because the HSM container might still be initializing.
     */
    private static void waitForHsmToken(String hsmTokenDir) throws InterruptedException {
        int maxWaitTime = 30;
        int elapsedTime = 0;
        int interval = 1;

        while (elapsedTime < maxWaitTime) {
            if (HsmExportedKeyLoader.areExportedKeysAvailable(hsmTokenDir)) {
                log.info("HSM exported keys are now available after {}s", elapsedTime);
                return;
            }
            Thread.sleep(interval * 1000);
            elapsedTime += interval;
        }

        log.warn("HSM exported keys still not available after {}s, proceeding anyway", maxWaitTime);
    }

    public static TrustConfig createTrustConfig(URI identifierRegistryUrl) {
        return TrustConfig.createTrustDid(identifierRegistryUrl);
    }

    private static boolean validateKeyPair(KeyPair keyPair) {
        try {
            if (keyPair == null || keyPair.getPrivate() == null || keyPair.getPublic() == null) {
                return false;
            }

            byte[] testData = "keypair-test".getBytes();

            Signature signature = Signature.getInstance("SHA256withECDSA");

            // Sign
            signature.initSign(keyPair.getPrivate());
            signature.update(testData);
            byte[] sig = signature.sign();

            // Verify
            signature.initVerify(keyPair.getPublic());
            signature.update(testData);

            return signature.verify(sig);

        } catch (Exception e) {
            return false;
        }
    }
}