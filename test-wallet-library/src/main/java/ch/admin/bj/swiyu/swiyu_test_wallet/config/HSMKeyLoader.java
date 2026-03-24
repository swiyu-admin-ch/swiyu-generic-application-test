package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class HSMKeyLoader {

    private static final Logger log = LoggerFactory.getLogger(HSMKeyLoader.class);

    public static KeyPair loadHsmKeyPair(String alias) {
        try {
            //String config = Files.readString(Paths.get(HSMConfig.PKCS11_CFG));

            Provider provider = Security.getProvider("SunPKCS11");
            if (provider == null) {
                provider = Security.getProvider("SunPKCS11");
            }

            Provider pkcs11Provider = provider.configure(HSMConfig.PKCS11_CFG);
            Security.addProvider(pkcs11Provider);

            KeyStore ks = KeyStore.getInstance("PKCS11", pkcs11Provider);
            ks.load(null, ("1234").toCharArray());

            if (!ks.containsAlias(alias)) {
                log.warn("Alias not found in HSM: {}", alias);
                return null;
            }

            Certificate cert = ks.getCertificate(alias);
            if (cert == null) {
                return null;
            }

            return new KeyPair(cert.getPublicKey(), null);

        } catch (Exception e) {
            log.error("Failed to load HSM key", e);
            return null;
        }
    }

}

