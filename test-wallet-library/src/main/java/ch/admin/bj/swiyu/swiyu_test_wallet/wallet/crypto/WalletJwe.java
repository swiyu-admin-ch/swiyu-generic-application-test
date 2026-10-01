package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto;

import com.nimbusds.jose.CompressionAlgorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import lombok.experimental.UtilityClass;

/**
 * Encrypts what the Wallet sends to a Verifier (the {@code direct_post.jwt} Authorization Response, OID4VP 1.0 §8.3.1).
 *
 * <p>The parameters are explicit and written from the specifications, not delegated to {@code swiyu-generic-java-lib}: the
 * Verifier decrypts with that library, so letting it also choose the parameters would hide a mismatch. Swiss verification
 * profile, Cryptography: ECDH-ES with a P-256 key and A256GCM; if zipping is possible, Deflate (DEF) is used. The Swiss VC
 * profile names A128GCM instead; the profiles disagree, see AGENTS.md.
 */
@UtilityClass
public class WalletJwe {

    public static final JWEAlgorithm ALGORITHM = JWEAlgorithm.ECDH_ES;
    public static final EncryptionMethod ENCRYPTION = EncryptionMethod.A256GCM;
    public static final CompressionAlgorithm COMPRESSION = CompressionAlgorithm.DEF;

    public static String encrypt(final String payload, final ECKey recipientPublicKey) {
        try {
            final JWEHeader header = new JWEHeader.Builder(ALGORITHM, ENCRYPTION)
                    .compressionAlgorithm(COMPRESSION)
                    .keyID(recipientPublicKey.getKeyID())
                    .build();
            final JWEObject jwe = new JWEObject(header, new Payload(payload));
            jwe.encrypt(new ECDHEncrypter(recipientPublicKey));
            return jwe.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot encrypt the payload for the recipient key", e);
        }
    }
}
