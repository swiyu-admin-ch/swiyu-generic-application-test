package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class HsmExportedKeyLoader {

    private static final Logger log = LoggerFactory.getLogger(HsmExportedKeyLoader.class);

    public static PublicKey loadPublicKeyFromDer(String derFilePath) {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(derFilePath));
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            log.error("Failed to load public key from DER file: {}", derFilePath, e);
            return null;
        }
    }

    /**
     * Load public key from X.509 certificate file
     */
    public static PublicKey loadPublicKeyFromCertificate(String certFilePath) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) factory.generateCertificate(
                    Files.newInputStream(Paths.get(certFilePath)));
            return cert.getPublicKey();
        } catch (Exception e) {
            log.error("Failed to load public key from certificate: {}", certFilePath, e);
            return null;
        }
    }

    /**
     * Load private key from classpath resource (resources/./softhsm/keys/key.pk8)
     */
    public static PrivateKey loadPrivateKeyFromResources(String tokenDir, String keyType) {
        try {
            ClassLoader classLoader = HsmExportedKeyLoader.class.getClassLoader();

            try (InputStream inputStream = classLoader.getResourceAsStream("./softhsm/keys/" + keyType + "-key.pk8" +
                    ".pem")) {
                if (inputStream == null) {
                    log.error("Private key file not found in resources: ./softhsm/keys/key.pk8.pem");
                    return null;
                }
                String pem = new String(inputStream.readAllBytes());
                String sanitized = pem
                        .replace("-----BEGIN PRIVATE KEY-----", "")
                        .replace("-----END PRIVATE KEY-----", "")
                        .replaceAll("\\s", "");
                byte[] keyBytes = java.util.Base64.getDecoder().decode(sanitized);
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("EC");

                PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

                log.info("Loaded private key from PEM: ./softhsm/keys/key.pk8.pem");

                return privateKey;
            }

        } catch (Exception e) {
            log.error("Failed to load private key from PEM resources", e);
            return null;
        }
    }

    public static KeyPair loadHsmExportedKeyPair(String tokenDir, String keyType) {
        try {
            Path exportDir = Paths.get(tokenDir, "exported");

            if (!Files.exists(exportDir)) {
                log.warn("Exported keys directory not found: {}", exportDir);
                return null;
            }

            final String pubKeyFile = String.format("%s_key_pub.der", keyType);
            final String certFile = String.format("%s.crt", keyType);

            Path pubKeyPath = exportDir.resolve(pubKeyFile);
            Path certPath = exportDir.resolve(certFile);

            PublicKey pubKey = null;

            if (Files.exists(pubKeyPath)) {
                pubKey = loadPublicKeyFromDer(pubKeyPath.toString());
                log.info("Loaded public key from DER: {}", pubKeyFile);
            }

            if (pubKey == null && Files.exists(certPath)) {
                pubKey = loadPublicKeyFromCertificate(certPath.toString());
                log.info("Loaded public key from certificate: {}", certFile);
            }

            if (pubKey == null) {
                log.error("Could not load public key for: {}", keyType);
                return null;
            }

            PrivateKey privKey = loadPrivateKeyFromResources(tokenDir, keyType);

            if (privKey == null) {
                log.warn("Could not load private key from resources, returning public key only");
                return new KeyPair(pubKey, null);
            }

            return new KeyPair(pubKey, privKey);

        } catch (Exception e) {
            log.error("Failed to load HSM exported key pair: {}", keyType, e);
            return null;
        }
    }
}

