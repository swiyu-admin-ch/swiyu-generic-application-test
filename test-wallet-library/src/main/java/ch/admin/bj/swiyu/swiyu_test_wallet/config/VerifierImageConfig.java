package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@Getter
@Setter
@ConfigurationProperties("application.verifier")
public class VerifierImageConfig {

    private String baseImage = "ghcr.io/swiyu-admin-ch/swiyu-verifier";
    private String imageTag = "latest";
}
