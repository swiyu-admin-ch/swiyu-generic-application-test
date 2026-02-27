package ch.admin.bj.swiyu.swiyu_test_wallet.registry;

import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import lombok.experimental.UtilityClass;

import org.bitcoinj.base.Base58;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

/**
 * Copied from didtoolbox-java <a href="https://github.com/swiyu-admin-ch/didtoolbox-java">...</a>
 * Should be replaced with didtoolbox-java
 */
@UtilityClass
public class KeyUtil {

    public static String getVerificationKeyMultibase(byte[] publicKeyEncoded) {

        var len = publicKeyEncoded.length;
        if (len < 32)
            throw new IllegalArgumentException("The supplied encoded Ed25519 public key must be at least of length 32 (bytes), but got " + len);

        var buff = ByteBuffer.allocate(32 + 2)
                .put((byte) 0xed) // Ed25519Pub/ed25519-pub is a draft code tagged "key" and described by: Ed25519 public key.
                .put((byte) 0x01)
                .put(Arrays.copyOfRange(publicKeyEncoded, publicKeyEncoded.length - 32, publicKeyEncoded.length));

        return 'z' + Base58.encode(buff.array());
    }

    public static byte[] generateSignature(KeyPair keypair, byte[] message) {
        try {
            var signer = Signature.getInstance("EdDSA");
            signer.initSign(keypair.getPrivate());
            signer.update(message);
            return signer.sign();
        } catch (SignatureException | InvalidKeyException | NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static KeyPair getEd25519VerificationMethodKeyPair() {

        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("Ed25519");
            keyPairGen.initialize(NamedParameterSpec.ED25519);

            return keyPairGen.generateKeyPair();

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static KeyPair generateEC256KeyPair() {

        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }

        keyPairGenerator.initialize(256);
        return keyPairGenerator.generateKeyPair();
    }

    public static String getPrivateKeyPem(KeyPair keyPair) {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(keyPair); // CAUTION The whole key pair is expected to be written here, not only the private key
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        return stringWriter.toString();
    }

    public static JWK createJWKFromKeyPair(KeyPair keyPair) {
        return new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic())
                .privateKey((ECPrivateKey) keyPair.getPrivate())
                .build();
    }
}
