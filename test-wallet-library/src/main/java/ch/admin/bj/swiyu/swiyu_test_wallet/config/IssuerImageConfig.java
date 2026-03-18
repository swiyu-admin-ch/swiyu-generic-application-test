package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import ch.admin.bj.swiyu.swiyu_test_wallet.util.JwtKeyGenerator;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@Getter
@Setter
@ConfigurationProperties("application.issuer")
public class IssuerImageConfig {

    // From application.yml and or env variables
    private String baseImage = "ghcr.io/swiyu-admin-ch/swiyu-issuer";
    private String imageTag = "latest";

    private String surname = "default";
    private boolean enforceDpop = false;
    private boolean signedMetadata = false;
    private boolean enableJwtAuth = false;
    private boolean encryptionEnforce = false;
    private boolean enableHsm = true;

    // HSM Configuration
    private String hsmHost = "softhsm";
    private int hsmPort = 5696;
    private String hsmUser = "admin";
    private String hsmPassword = "password";
    private String hsmUserPin = "1234";
    private String hsmKeyId = "01";
    private String hsmKeyPin = "1234";
    private String hsmStatusKeyId = "01";
    private String hsmStatusKeyPin = "1234";
    private String hsmLibPath = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so";
    private String hsmConfigPath = "/tmp/pkcs11.cfg";

    private JwtKeyGenerator jwtKeyGenerator;

    // set dynamically
    private String mockServerUri;
    private String swiyuPartnerId;
    private String issuerServiceUrl;
    private String issuerRegistryEntry;
    private String issuerDid;
    private String issuerDidLog;
    private String issuerAssertKeyId;
    private String issuerAuthKeyId;
    private String issuerAssertKeyPemString;
    private String issuerAuthKeyPemString;

    public String getDbSchema() {
        return String.format("%s_%s", DBContainerConfig.ISSUER_DB_SCHEMA, getSurname());
    }

    public String getNetworkAlias() {
        return String.format("swiyu_issuer_%s", getSurname());
    }

    public JwtKeyGenerator getJwtKeyGenerator() {
        if (enableJwtAuth && jwtKeyGenerator == null) {
            jwtKeyGenerator = new JwtKeyGenerator("test-key-1");
        }
        return jwtKeyGenerator;
    }
}
