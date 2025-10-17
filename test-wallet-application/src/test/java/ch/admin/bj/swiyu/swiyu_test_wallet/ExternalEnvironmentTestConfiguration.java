package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.EnvironmentConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;

import java.net.URI;
import java.util.UUID;

/**
 * External profile: Do not start Testcontainers containers. Provide only IssuerConfig.
 */
@TestConfiguration(proxyBeanMethods = false)
@Profile("external")
public class ExternalEnvironmentTestConfiguration {

    @Bean
    public IssuerConfig issuerConfig(@Value("${EXTERNAL_DID_BASE:https://external-did-base.example}") String didBase) {
        UUID id = UUID.randomUUID();
        return EnvironmentConfig.createIssueraConfig(URI.create(didBase + "/" + id));
    }
}

