package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class RegressionPropertiesTest {

    @Test
    void bindsEnvironmentVariablesAndKeepsDefaults() {
        final RegressionProperties properties = bind(new SystemEnvironmentPropertySource(
                StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                Map.of(
                        "REGRESSION_ISSUER_PREVIOUS_VERSION", "4.1.0",
                        "REGRESSION_ISSUER_CANDIDATE_VERSION", "4.2.0",
                        "REGRESSION_ISSUER_CANDIDATE_VARIANT", "STRICT",
                        "REGRESSION_VERIFIER_PREVIOUS_VERSION", "4.1.1",
                        "REGRESSION_VERIFIER_CANDIDATE_VERSION", "4.2.1",
                        "REGRESSION_VERIFIER_PREVIOUS_METADATA", "file:/tmp/verifier-previous.json"
                )));

        assertThat(properties.getIssuer().getPrevious().getVersion()).isEqualTo("4.1.0");
        assertThat(properties.getIssuer().getPrevious().getVariant()).isEqualTo("DEFAULT");
        assertThat(properties.getIssuer().getPrevious().getMetadata())
                .isEqualTo("classpath:issuer/metadata.json");
        assertThat(properties.getIssuer().getCandidate().getVariant()).isEqualTo("STRICT");
        assertThat(properties.getVerifier().getPrevious().getVersion()).isEqualTo("4.1.1");
        assertThat(properties.getVerifier().getPrevious().getMetadata())
                .isEqualTo("file:/tmp/verifier-previous.json");
        assertThat(properties.getVerifier().getCandidate().getVersion()).isEqualTo("4.2.1");
        assertThat(properties.getVerifier().getCandidate().getMetadata())
                .isEqualTo("classpath:verifier/metadata.json");
    }

    @Test
    void bindsSystemProperties() {
        final Map<String, String> systemProperties = new LinkedHashMap<>();
        systemProperties.put("regression.issuer.previous.version", "4.0.0");
        systemProperties.put("regression.issuer.previous.variant", "signed-metadata");
        systemProperties.put("regression.issuer.previous.metadata", "file:/tmp/issuer-previous.json");
        systemProperties.put("regression.issuer.candidate.version", "4.1.0");

        final RegressionProperties properties = bindSystemProperties(systemProperties);

        assertThat(properties.getIssuer().getPrevious().getVersion()).isEqualTo("4.0.0");
        assertThat(properties.getIssuer().getPrevious().getVariant()).isEqualTo("signed-metadata");
        assertThat(properties.getIssuer().getPrevious().getMetadata())
                .isEqualTo("file:/tmp/issuer-previous.json");
        assertThat(properties.getIssuer().getCandidate().getVersion()).isEqualTo("4.1.0");
    }

    private static RegressionProperties bind(final MapPropertySource propertySource) {
        final ConfigurableEnvironment environment = new StandardEnvironment();
        if (propertySource instanceof SystemEnvironmentPropertySource) {
            environment.getPropertySources().replace(
                    StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                    propertySource);
        } else {
            environment.getPropertySources().addFirst(propertySource);
        }
        return bind(environment);
    }

    private static RegressionProperties bindSystemProperties(final Map<String, String> values) {
        final Map<String, String> previousValues = new LinkedHashMap<>();
        values.forEach((key, value) -> {
            previousValues.put(key, System.getProperty(key));
            System.setProperty(key, value);
        });

        try {
            return bind(new StandardEnvironment());
        } finally {
            previousValues.forEach((key, value) -> {
                if (value == null) {
                    System.clearProperty(key);
                } else {
                    System.setProperty(key, value);
                }
            });
        }
    }

    private static RegressionProperties bind(final ConfigurableEnvironment environment) {
        return Binder.get(environment)
                .bind("regression", Bindable.of(RegressionProperties.class))
                .orElseThrow(() -> new AssertionError("Regression properties were not bound"));
    }
}
