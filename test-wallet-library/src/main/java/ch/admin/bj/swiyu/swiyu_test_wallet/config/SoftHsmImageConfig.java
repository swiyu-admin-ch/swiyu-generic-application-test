package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@Getter
@Setter
@ConfigurationProperties("application.softhsm")
public class SoftHsmImageConfig {

    private String tokenLabel = "dev-token";
    private String pin = "1234";
    private String soPin = "5678";
    private String keyLabel = "dev-issuer";
    private String signingAlgorithm = "ES512";
    private String networkAlias = "softhsm";
}

