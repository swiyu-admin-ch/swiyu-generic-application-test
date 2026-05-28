package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties("application.container-logs")
public class ContainerLogConfig {

    private boolean issuer = true;
    private boolean verifier = true;
    private boolean db = false;
    private boolean mockServer = false;
    private boolean softHsm = false;
}
