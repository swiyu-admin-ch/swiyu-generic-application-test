package ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.TrustConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.DidLogUtil.createDidLog;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.DidLogUtil.getDidFromDidLog;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil.createJWKFromKeyPair;

/** Builds an isolated Ed25519 Trust Registry DID for crypto-agility E2E scenarios. */
public final class Tp2TrustConfigFactory {

    private Tp2TrustConfigFactory() {
    }

    public static TrustConfig createEd25519TrustConfig(URI identifierRegistryUrl) {
        try {
            KeyPair authKeys = generateP256KeyPair();
            OctetKeyPair assertionKey = new OctetKeyPairGenerator(Curve.Ed25519).generate();
            String didLog = createDidLog(
                    createJWKFromKeyPair(authKeys),
                    assertionKey,
                    identifierRegistryUrl
            );
            String trustDid = getDidFromDidLog(didLog);

            return TrustConfig.builder()
                    .trustDid(trustDid)
                    .trustDidLog(didLog)
                    .trustAssertKeyId(trustDid + "#assert-key-01")
                    .trustEd25519AssertKeyId(trustDid + "#assert-key-01")
                    .trustAuthKeyId(trustDid + "#auth-key-01")
                    .trustAuthKeyPemString(KeyUtil.getPrivateKeyPem(authKeys))
                    .trustEd25519AssertKey(assertionKey)
                    .build();
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot generate Ed25519 Trust Registry test keys", e);
        }
    }

    private static KeyPair generateP256KeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
            return keyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot generate P-256 Trust Registry authentication keys", e);
        }
    }
}
