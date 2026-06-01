package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil;
import lombok.Builder;
import lombok.Getter;

import java.net.URI;
import java.security.KeyPair;

import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.DidLogUtil.createDidLog;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.DidLogUtil.getDidFromDidLog;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil.createJWKFromKeyPair;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil.generateEC256KeyPair;

@Getter
@Builder
public class VerifierConfig {

    private final String mockServerUri;
    private final String verifierDid;
    private final String verifierDidLog;
    private final String verifierAuthKeyId;
    private final String verifierAuthKeyPemString;

    public static VerifierConfig createVerifierConfig(final URI identifierRegistryUrl) {
        KeyPair authKeys = generateEC256KeyPair();
        KeyPair assertKeys = generateEC256KeyPair();

        var authJwk = createJWKFromKeyPair(authKeys);
        var assertJwk = createJWKFromKeyPair(assertKeys);

        var didLog = createDidLog(authJwk, assertJwk, identifierRegistryUrl);
        var verifierDid = getDidFromDidLog(didLog);

        return VerifierConfig.builder()
                .mockServerUri(String.format("http://%s", MockServerClientConfig.MOCKSERVER_HOST))
                .verifierDid(verifierDid)
                .verifierDidLog(didLog)
                .verifierAuthKeyId(verifierDid + "#auth-key-01")
                .verifierAuthKeyPemString(KeyUtil.getPrivateKeyPem(authKeys))
                .build();
    }
}
