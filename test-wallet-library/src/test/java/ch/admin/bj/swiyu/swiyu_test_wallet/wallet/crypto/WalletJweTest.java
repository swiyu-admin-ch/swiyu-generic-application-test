package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto;

import ch.admin.bj.swiyu.jweutil.JweUtil;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Specification: OID4VP 1.0 §8.3.1 (`direct_post.jwt`), Swiss verification profile (ECDH-ES, P-256, A256GCM; Deflate when
 * zipping is possible). The Verifier decrypts with {@link JweUtil}, which is used here as the reference for "the
 * Verifier can read this".
 */
class WalletJweTest {

    private static final String PAYLOAD = "{\"vp_token\":{\"credential_query\":[\"eyJ...~eyJ...\"]},\"state\":\"s-123\"}";

    private ECKey verifierKey;

    @BeforeEach
    void setUp() throws Exception {
        verifierKey = new ECKeyGenerator(Curve.P_256).keyID("verifier-key-1").generate();
    }

    @Test
    void encrypt_whenCalled_thenUsesTheAlgorithmsOfTheSwissProfileAndTheRecipientKeyId() throws Exception {
        final JWEObject jwe = JWEObject.parse(WalletJwe.encrypt(PAYLOAD, verifierKey.toPublicJWK()));

        assertThat(jwe.getHeader().getAlgorithm().getName())
                .isEqualTo("ECDH-ES");
        assertThat(jwe.getHeader().getEncryptionMethod().getName())
                .isEqualTo("A256GCM");
        assertThat(jwe.getHeader().getCompressionAlgorithm().getName())
                .isEqualTo("DEF");
        assertThat(jwe.getHeader().getKeyID())
                .as("the Verifier picks its decryption key by kid")
                .isEqualTo("verifier-key-1");
    }

    @Test
    void encrypt_whenCalled_thenOnlyTheRecipientCanReadThePayload() throws Exception {
        final String compact = WalletJwe.encrypt(PAYLOAD, verifierKey.toPublicJWK());

        final JWEObject jwe = JWEObject.parse(compact);
        jwe.decrypt(new ECDHDecrypter(verifierKey));
        assertThat(jwe.getPayload().toString())
                .as("independent decryption with Nimbus")
                .isEqualTo(PAYLOAD);
        assertThat(JweUtil.decrypt(compact, verifierKey))
                .as("reference: the library the Verifier decrypts with")
                .isEqualTo(PAYLOAD);
    }

    @Test
    void encrypt_whenTwoEncryptionsOfTheSamePayload_thenTheCiphertextsDiffer() {
        assertThat(WalletJwe.encrypt(PAYLOAD, verifierKey.toPublicJWK()))
                .isNotEqualTo(WalletJwe.encrypt(PAYLOAD, verifierKey.toPublicJWK()));
    }
}
