package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil;
import lombok.experimental.UtilityClass;

import java.net.URI;
import java.security.KeyPair;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.DidLogUtil.createDidLog;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.DidLogUtil.getDidFromDidLog;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil.createJWKFromKeyPair;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil.generateEC256KeyPair;

@UtilityClass
public class EnvironmentConfig {
    public static IssuerConfig createIssueraConfig(URI identifierRegistryUrl) {
        KeyPair assertKeys = generateEC256KeyPair();
        KeyPair authKeys = generateEC256KeyPair();

        var assertJwk = createJWKFromKeyPair(assertKeys);
        var authJwk = createJWKFromKeyPair(authKeys);

        var didLog = createDidLog(authJwk, assertJwk, identifierRegistryUrl);
        var issuerDid = getDidFromDidLog(didLog);

        return IssuerConfig.builder()
                .swiyuPartnerId(UUID.randomUUID().toString())
                .issuerRegistryEntry(identifierRegistryUrl.toString())
                .issuerDid(issuerDid)
                .issuerDidLog(didLog)
                .mockServerUri("https://mockserver:1080")
                .issuerAssertKeyId(issuerDid + "#assert-key-01")
                .issuerAuthKeyId(issuerDid + "#assert-key-01")
                .issuerAssertKeyPemString(KeyUtil.getPrivateKeyPem(assertKeys))
                .issuerAuthKeyPemString(KeyUtil.getPrivateKeyPem(authKeys))
                .build();
    }
}
