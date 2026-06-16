package ch.admin.bj.swiyu.swiyu_test_wallet.environment;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ManagementAuthConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import org.testcontainers.containers.GenericContainer;

public record VerifierHandle(
        VerifierVariant variant,
        VerifierConfig config,
        VerifierImageConfig imageConfig,
        GenericContainer<?> container,
        VerifierManager manager,
        ServiceLocationContext serviceLocation,
        ManagementAuthConfig managementAuthConfig,
        String managementAccessToken
) {
    public String serviceUrl() {
        return "http://%s:%d".formatted(container.getHost(), container.getMappedPort(8080));
    }
}
