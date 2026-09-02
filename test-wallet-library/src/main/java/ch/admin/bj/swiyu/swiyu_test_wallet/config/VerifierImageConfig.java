package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@Getter
@Setter
@ConfigurationProperties("application.verifier")
public class VerifierImageConfig {

    private String baseImage = "ghcr.io/swiyu-admin-ch/swiyu-verifier";
    private String imageTag = "latest";

    private String swiyuPartnerId;


    private String surname = "default";
    private boolean enableHsm = false;
    private boolean multipleSigningKeys = false;
    private long trustRegistryMaxCacheSize = 0;
    private long trustRegistryMaxCacheTtlSeconds = 0;
    private long jwkCacheTtlMillis = 0;
    private long trustStatementCacheTtlMillis = 0;
    private int requestObjectTtlSeconds = 0;
    private boolean rejectSuspendedCredentials = false;

    private String hsmUser = "admin";
    private String hsmPassword = "password";
    private String hsmUserPin = "1234";
    private String hsmKeyId = "01";
    private String hsmKeyPin = "1234";

    public String getDbSchema() {
        return String.format("%s_%s", DBContainerConfig.VERIFIER_DB_SCHEMA, getSurname());
    }

    public String getNetworkAlias() {
        return String.format("swiyu_verifier_%s", getSurname());
    }
}
