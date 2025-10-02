package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@Data
@ConfigurationProperties(prefix = "application")
public class ApplicationProperties {

    private String issuerServiceUrl = "http://swiyu-issuer-service:8080/management";
}
