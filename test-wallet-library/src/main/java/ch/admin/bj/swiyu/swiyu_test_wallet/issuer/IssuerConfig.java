package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.HsmExportedKeyLoader;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil;
import lombok.Builder;
import lombok.Data;

import java.net.URI;
import java.security.KeyPair;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.DidLogUtil.createDidLog;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.DidLogUtil.getDidFromDidLog;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil.createJWKFromKeyPair;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil.generateEC256KeyPair;

@Builder
@Data
public class IssuerConfig {

    private String mockServerUri;
    private String swiyuPartnerId;
    private String issuerServiceUrl;
    private String issuerRegistryEntry;
    private String issuerDid;
    private String issuerDidLog;
    private String issuerAssertKeyId;
    private String issuerAuthKeyId;
    private String issuerAssertKeyPemString;
    private String issuerAuthKeyPemString;

    private KeyPair keyPair;

    public static IssuerConfig createIssuerConfig(final URI identifierRegistryUrl,
                                                  final boolean enableHsm,
                                                  final String hsmTokenDir) {

        KeyPair assertKeys;
        KeyPair authKeys;

        if (enableHsm && hsmTokenDir != null) {
            assertKeys = HsmExportedKeyLoader.loadHsmExportedKeyPair(hsmTokenDir, "01");
            authKeys = HsmExportedKeyLoader.loadHsmExportedKeyPair(hsmTokenDir, "02");
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
                .issuerAuthKeyId(issuerDid + "#auth-key-01")
                .issuerAssertKeyPemString(assertKeyPem)
                .issuerAuthKeyPemString(authKeyPem)
                .keyPair(assertKeys)
                .build();
    }
}
