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

    private String baseImage = "ghcr.io/swiyu-admin-ch/swiyu-issuer";
    private String imageTag = "latest";
}
