package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.RegressionProperties;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerRuntimeFactory;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierRuntimeFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.PostgreSQLContainer;

/** Enables version-transition orchestration only for tests that explicitly import this configuration. */
@TestConfiguration(proxyBeanMethods = false)
@EnableConfigurationProperties(RegressionProperties.class)
public class RegressionEnvironmentTestConfiguration {

    @Bean
    public RegressionImageResolver regressionImageResolver() {
        return new RegressionImageResolver();
    }

    @Bean
    public RegressionEnvironmentFactory regressionEnvironmentFactory(
            final RegressionProperties regressionProperties,
            final IssuerImageConfig issuerImageConfig,
            final VerifierImageConfig verifierImageConfig,
            final IssuerRuntimeFactory issuerRuntimeFactory,
            final VerifierRuntimeFactory verifierRuntimeFactory,
            final PostgreSQLContainer<?> database,
            final RegressionImageResolver regressionImageResolver) {
        return new RegressionEnvironmentFactory(
                regressionProperties,
                issuerImageConfig,
                verifierImageConfig,
                issuerRuntimeFactory,
                verifierRuntimeFactory,
                database,
                regressionImageResolver
        );
    }
}
