package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import lombok.experimental.UtilityClass;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

@UtilityClass
public class ECCryptoSupport {
    public static KeyPair generateECKeyPair() {
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("EC");
            var ecSpec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(ecSpec);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e);
        }
    }

    public static ECDSASigner createECDSASigner(PrivateKey privateKey) {
        try {
            if (!(privateKey instanceof ECPrivateKey)) {
                throw new IllegalArgumentException("Private key must be an instance of ECPrivateKey");
            }
            return new ECDSASigner((ECPrivateKey) privateKey);
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public static ECKey toPublicJwk(final PublicKey publicKey, final String keyId) {
        if (!(publicKey instanceof ECPublicKey)) {
            throw new IllegalArgumentException("Public key must be an instance of ECPublicKey");
        }
        final ECKey.Builder builder = new ECKey.Builder(Curve.P_256, (ECPublicKey) publicKey);
        if (keyId != null) {
            builder.keyID(keyId);
        }

        return builder.build();
    }
}
