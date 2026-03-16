package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.net.URI;
import java.security.KeyPair;

import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.DidLogUtil.createDidLog;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.DidLogUtil.getDidFromDidLog;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil.createJWKFromKeyPair;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil.generateEC256KeyPair;

@Getter
@Builder
@ToString
public class TrustConfig {

    private final String trustDid;
    private final String trustDidLog;
    private final String trustAssertKeyId;
    private final String trustAuthKeyId;
    private final String trustAssertKeyPemString;
    private final String trustAuthKeyPemString;

    public static TrustConfig createTrustDid(URI identifierRegistryUrl) {
        KeyPair assertKeys = generateEC256KeyPair();
        KeyPair authKeys = generateEC256KeyPair();

        var assertJwk = createJWKFromKeyPair(assertKeys);
        var authJwk = createJWKFromKeyPair(authKeys);

        var didLog = createDidLog(authJwk, assertJwk, identifierRegistryUrl);
        var trustDid = getDidFromDidLog(didLog);

        return TrustConfig.builder()
                .trustDid(trustDid)
                .trustDidLog(didLog)
                .trustAssertKeyId(trustDid + "#assert-key-01")
                .trustAuthKeyId(trustDid + "#assert-key-01")
                .trustAssertKeyPemString(KeyUtil.getPrivateKeyPem(assertKeys))
                .trustAuthKeyPemString(KeyUtil.getPrivateKeyPem(authKeys))
                .build();
    }
}

