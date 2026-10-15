package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import ch.admin.bj.swiyu.swiyu_test_wallet.identity.KeyUtil;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.HsmExportedKeyLoader;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.net.URI;
import java.security.KeyPair;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mockStatic;

class VerifierConfigTest {

    @Test
    void hsmVerifierIdentity_whenCreated_thenDidPublishesTheTokenPublicKeys() throws Exception {
        // Given
        final KeyPair defaultKey = KeyUtil.generateEC256KeyPair();
        final KeyPair alternateKey = KeyUtil.generateEC256KeyPair();
        final ECKey defaultJwk = KeyUtil.createJWKFromKeyPair(defaultKey).toECKey();
        final ECKey alternateJwk = KeyUtil.createJWKFromKeyPair(alternateKey).toECKey();

        try (MockedStatic<HsmExportedKeyLoader> keys = mockStatic(HsmExportedKeyLoader.class)) {
            keys.when(() -> HsmExportedKeyLoader.loadHsmResourceKeyPair("01")).thenReturn(defaultKey);
            keys.when(() -> HsmExportedKeyLoader.loadHsmResourceKeyPair("02")).thenReturn(alternateKey);

            // When
            final VerifierConfig config = VerifierConfig.createHsmVerifierConfig(
                    URI.create("https://mockserver/api/v1/did/hsm-verifier"));

            // Then
            assertThat(config.getVerifierDidLog())
                    .contains(defaultJwk.getX().toString(), defaultJwk.getY().toString())
                    .contains(alternateJwk.getX().toString(), alternateJwk.getY().toString())
                    .doesNotContain("\"d\":");
            assertThat(JWK.parseFromPEMEncodedObjects(config.getVerifierAuthKeyPemString()).toECKey().toECPublicKey())
                    .isEqualTo(defaultKey.getPublic());
            assertThat(config.getVerifierAuthKeyId())
                    .isEqualTo(config.getVerifierDid() + "#auth-key-01");
        }
    }
}
