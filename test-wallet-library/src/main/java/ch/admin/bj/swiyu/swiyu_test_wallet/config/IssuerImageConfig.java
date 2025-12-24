package ch.admin.bj.swiyu.swiyu_test_wallet.config;

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
}
