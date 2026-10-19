package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@Getter
@Setter
@ConfigurationProperties("application.verifier")
// Each field maps to an independently configured issuer or verifier image property.
public class VerifierImageConfig {

    private String baseImage = "ghcr.io/swiyu-admin-ch/swiyu-verifier";
    private String imageTag = "latest";

    private String swiyuPartnerId;


    private String surname = "default";
    private boolean enableHsm;
    private boolean multipleSigningKeys;
    private boolean omitStaticVerifierDid;
    private long trustRegistryMaxCacheSize;
    private long trustRegistryMaxCacheTtlSeconds;
    private long jwkCacheTtlMillis;
    private long trustStatementCacheTtlMillis;
    private int requestObjectTtlSeconds;
    private boolean rejectSuspendedCredentials;

    // Null leaves the environment variable unset to exercise the verifier's production default.
    private Boolean auditVpTokenEnabled = true;
    private Boolean auditCredentialSubjectDataEnabled = true;
    private Boolean auditCredentialEvaluationEnabled = true;

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
