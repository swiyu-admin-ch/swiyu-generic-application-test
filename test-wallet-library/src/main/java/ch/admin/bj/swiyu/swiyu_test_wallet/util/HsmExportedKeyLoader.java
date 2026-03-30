package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import ch.admin.bj.swiyu.jwssignatureservice.dto.SignatureConfigurationDto;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategy;
import com.nimbusds.jose.jwk.JWK;
import lombok.extern.slf4j.Slf4j;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

@Slf4j
public class HsmExportedKeyLoader {

    /**
     * Load public key from X.509 certificate file
     */
    public static PublicKey loadPublicKeyFromCertificate(final String certFilePath) {
        try {
            final String pemCert = Files.readString(Paths.get(certFilePath));
            final JWK jwk = JWK.parseFromPEMEncodedX509Cert(pemCert);

            return jwk.toECKey().toPublicKey();
        } catch (Exception e) {
            log.error("Failed to load public key from certificate", e);
            return null;
        }
    }

    /**
     * Load private key from classpath resource (resources/softhsm/keys/key.pk8)
     */
    public static PrivateKey loadPrivateKeyFromResources(final String keyId) {
        try {
            final ClassLoader classLoader = HsmExportedKeyLoader.class.getClassLoader();
            final String relativeResourcePath = String.format("softhsm/keys/%s-key.pem", keyId);

            try (final InputStream inputStream = classLoader.getResourceAsStream(relativeResourcePath)) {

                if (inputStream == null) {
                    log.error("Private key file not found in resources: {}", relativeResourcePath);
                    return null;
                }

                final String pem = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
                final JWK jwk = JWK.parseFromPEMEncodedObjects(pem);
                final PrivateKey privateKey = jwk.toECKey().toECPrivateKey();

                log.info("Loaded private key from PEM: {}", relativeResourcePath);

                return privateKey;
            }

        } catch (Exception e) {
            log.error("Failed to load private key from PEM resources", e);
            return null;
        }
    }

    public static KeyPair loadHsmExportedKeyPair(String tokenDir, String keyId) {
        try {
            Path exportDir = Paths.get(tokenDir, "exported");

            if (!Files.exists(exportDir)) {
                log.warn("Exported keys directory not found");
                return null;
            }

            final String certFile = String.format("%s.crt", keyId);
            final Path certPath = exportDir.resolve(certFile);

            PublicKey pubKey = null;
            if (Files.exists(certPath)) {
                pubKey = loadPublicKeyFromCertificate(certPath.toString());
                log.info("Loaded public key from certificate: {}", certFile);
            }
            if (pubKey == null) {
                log.error("Could not load public key for: {} ({})", certPath, keyId);
                return null;
            }

            final PrivateKey privKey = loadPrivateKeyFromResources(keyId);

            if (privKey == null) {
                log.warn("Could not load private key from resources, returning public key only");
                return new KeyPair(pubKey, null);
            }

            return new KeyPair(pubKey, privKey);

        } catch (Exception e) {
            log.error("Failed to load HSM exported key pair: {}", keyId, e);
            return null;
        }
    }
}

