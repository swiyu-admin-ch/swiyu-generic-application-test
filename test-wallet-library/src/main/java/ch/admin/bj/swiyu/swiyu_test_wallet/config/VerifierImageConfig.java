package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties("application.verifier")
public class VerifierImageConfig {

    private String baseImage = "ghcr.io/swiyu-admin-ch/swiyu-verifier";
    private String imageTag = "latest";

    private String swiyuPartnerId;


    private String surname = "default";

    public String getDbSchema() {
        return String.format("%s_%s", DBContainerConfig.VERIFIER_DB_SCHEMA, getSurname());
    }

    public String getNetworkAlias() {
        return String.format("swiyu_verifier_%s", getSurname());
    }
}
