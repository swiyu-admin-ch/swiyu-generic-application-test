package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import ch.admin.bj.swiyu.swiyu_test_wallet.identity.KeyUtil;
import ch.admin.bj.swiyu.swiyu_test_wallet.mock.MockServices;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.HsmExportedKeyLoader;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.net.URI;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.List;

import static ch.admin.bj.swiyu.swiyu_test_wallet.identity.DidLogUtil.createDidLog;
import static ch.admin.bj.swiyu.swiyu_test_wallet.identity.DidLogUtil.getDidFromDidLog;
import static ch.admin.bj.swiyu.swiyu_test_wallet.identity.KeyUtil.generateEC256KeyPair;

@Getter
@Builder
public class VerifierConfig {

    private final String mockServerUri;
    private final String verifierDid;
    private final String verifierDidLog;
    private final String verifierAuthKeyId;
    private final String verifierAuthKeyPemString;

    @Builder.Default
    @Setter
    private List<VerifierConfig> additionalSigningIdentities = List.of();

    public static VerifierConfig createVerifierConfig(final URI identifierRegistryUrl) {
        return createVerifierConfig(identifierRegistryUrl, generateEC256KeyPair(), generateEC256KeyPair());
    }

    /** Publishes the default SoftHSM signing key and the alternate test key in the Verifier DID. */
    public static VerifierConfig createHsmVerifierConfig(final URI identifierRegistryUrl) {
        return createVerifierConfig(identifierRegistryUrl,
                HsmExportedKeyLoader.loadHsmResourceKeyPair("01"),
                HsmExportedKeyLoader.loadHsmResourceKeyPair("02"));
    }

    private static VerifierConfig createVerifierConfig(final URI identifierRegistryUrl,
                                                       final KeyPair authKeys,
                                                       final KeyPair assertKeys) {

        var didLog = createDidLog((ECPublicKey) authKeys.getPublic(), (ECPublicKey) assertKeys.getPublic(), identifierRegistryUrl);
        var verifierDid = getDidFromDidLog(didLog);

        return VerifierConfig.builder()
                .mockServerUri(String.format("http://%s", MockServices.MOCKSERVER_HOST))
                .verifierDid(verifierDid)
                .verifierDidLog(didLog)
                .verifierAuthKeyId(verifierDid + "#auth-key-01")
                .verifierAuthKeyPemString(KeyUtil.getPrivateKeyPem(authKeys))
                .build();
    }
}
