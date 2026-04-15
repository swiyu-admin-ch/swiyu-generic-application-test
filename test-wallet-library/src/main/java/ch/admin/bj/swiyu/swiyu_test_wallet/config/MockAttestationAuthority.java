package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil;
import com.nimbusds.jose.jwk.ECKey;
import lombok.Getter;

import java.net.URI;
import java.security.KeyPair;
import java.security.PrivateKey;

import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.DidLogUtil.createDidLog;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.DidLogUtil.getDidFromDidLog;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil.createJWKFromKeyPair;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil.generateEC256KeyPair;

@Getter
public class MockAttestationAuthority {

    private final String did;
    private final String didLog;
    private final String kid;
    private final PrivateKey signingPrivateKey;
    private final ECKey signingPublicJwk;

    public MockAttestationAuthority(final URI identifierRegistryUrl) {
        final KeyPair assertKeys = generateEC256KeyPair();
        final KeyPair authKeys = generateEC256KeyPair();

        final ECKey assertJwk = createJWKFromKeyPair(assertKeys).toECKey();
        final ECKey authJwk = createJWKFromKeyPair(authKeys).toECKey();

        this.didLog = createDidLog(authJwk, assertJwk, identifierRegistryUrl);
        this.did = getDidFromDidLog(didLog);
        this.kid = did + "#assert-key-01";
        this.signingPrivateKey = assertKeys.getPrivate();
        this.signingPublicJwk = assertJwk.toPublicJWK();
    }

    private MockAttestationAuthority(final String did, final String didLog, final String kid, final PrivateKey signingPrivateKey, final ECKey signingPublicJwk) {
        this.did = did;
        this.didLog = didLog;
        this.kid = kid;
        this.signingPrivateKey = signingPrivateKey;
        this.signingPublicJwk = signingPublicJwk;
    }

    public MockAttestationAuthority withMismatchedSigningKey() {
        final KeyPair unrelatedKeyPair = generateEC256KeyPair();
        return new MockAttestationAuthority(
                this.did,
                this.didLog,
                this.kid,
                unrelatedKeyPair.getPrivate(),
                createJWKFromKeyPair(unrelatedKeyPair).toECKey().toPublicJWK()
        );
    }
}

