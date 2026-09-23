package ch.admin.bj.swiyu.swiyu_test_wallet.environment;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.ContainerLogConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.HSMConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.HSMContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.KeycloakContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ManagementAuthConfig;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;

import java.util.Map;
import java.util.function.Supplier;

/**
 * Provides optional Keycloak and SoftHSM infrastructure shared by component runtimes.
 *
 * <p>Each service is started lazily at most once per provider instance and retained for subsequent runtimes. Individual
 * Issuer and Verifier transitions do not own or stop these shared containers. Synchronized access prevents duplicate
 * startup when tests request the same service concurrently.
 */
public final class EnvironmentSupportServices {

    private final Network network;
    private final ManagementAuthConfig managementAuthTemplate;
    private final HSMConfig hsmConfig;
    private final ContainerLogConfig containerLogConfig;
    private final String hsmTokenDirectory;

    private GenericContainer<?> keycloakContainer;
    private GenericContainer<?> softHsmContainer;

    public EnvironmentSupportServices(
            final Network network,
            final ManagementAuthConfig managementAuthTemplate,
            final HSMConfig hsmConfig,
            final ContainerLogConfig containerLogConfig,
            final String tokenDirPath) {
        this.network = network;
        this.managementAuthTemplate = managementAuthTemplate;
        this.hsmConfig = hsmConfig;
        this.containerLogConfig = containerLogConfig;
        this.hsmTokenDirectory = tokenDirPath;
    }

    /** Returns the shared running Keycloak container, starting it on first access. */
    public synchronized GenericContainer<?> keycloak() {
        if (keycloakContainer == null) {
            keycloakContainer = startSupportService(() ->
                    KeycloakContainerConfig.createKeycloakContainer(network, managementAuth(true))
            );
        }
        ensureRunning("keycloak", keycloakContainer);
        return keycloakContainer;
    }

    /** Returns the shared running SoftHSM container, starting it on first access. */
    public synchronized GenericContainer<?> softHsm() {
        if (softHsmContainer == null) {
            softHsmContainer = startSupportService(() ->
                    HSMContainerConfig.createSoftHsmContainer(
                            network,
                            hsmConfig,
                            hsmTokenDirectory,
                            containerLogConfig
                    )
            );
        }
        ensureRunning("softHSM", softHsmContainer);
        return softHsmContainer;
    }

    /**
     * Creates an independent management-auth configuration from the environment template.
     *
     * <p>Changing the returned object does not mutate the shared template.
     */
    public ManagementAuthConfig managementAuth(final boolean enabled) {
        final ManagementAuthConfig config = new ManagementAuthConfig();
        config.setEnabled(enabled);
        config.setKeycloakImage(managementAuthTemplate.getKeycloakImage());
        config.setRealm(managementAuthTemplate.getRealm());
        config.setNetworkAlias(managementAuthTemplate.getNetworkAlias());
        config.setPort(managementAuthTemplate.getPort());
        config.setIssuerClientId(managementAuthTemplate.getIssuerClientId());
        config.setIssuerClientSecret(managementAuthTemplate.getIssuerClientSecret());
        config.setVerifierClientId(managementAuthTemplate.getVerifierClientId());
        config.setVerifierClientSecret(managementAuthTemplate.getVerifierClientSecret());
        config.setJwsAlgorithms(managementAuthTemplate.getJwsAlgorithms());
        return config;
    }

    /** Requests an Issuer client-credentials token, starting Keycloak if necessary. */
    public String issuerManagementAccessToken(final ManagementAuthConfig config) {
        return clientCredentialsToken(config.getIssuerClientId(), config.getIssuerClientSecret());
    }

    /** Requests a Verifier client-credentials token, starting Keycloak if necessary. */
    public String verifierManagementAccessToken(final ManagementAuthConfig config) {
        return clientCredentialsToken(config.getVerifierClientId(), config.getVerifierClientSecret());
    }

    public String tokenDirPath() {
        return hsmTokenDirectory;
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private static GenericContainer<?> startSupportService(
            final Supplier<GenericContainer<?>> containerSupplier) {
        final GenericContainer<?> container = containerSupplier.get();
        try {
            container.start();
            return container;
        } catch (RuntimeException | Error failure) {
            stopAfterFailedStart(container, failure);
            throw failure;
        }
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private static void stopAfterFailedStart(
            final GenericContainer<?> container,
            final Throwable failure) {
        try {
            container.stop();
        } catch (RuntimeException | Error stopFailure) {
            failure.addSuppressed(stopFailure);
        }
    }

    private String clientCredentialsToken(final String clientId, final String clientSecret) {
        final MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "client_credentials");
        formData.add("client_id", clientId);
        formData.add("client_secret", clientSecret);

        final Map<?, ?> response = RestClient.builder().build().post()
                .uri(managementAuth(true).getHostTokenUri(keycloak()))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(formData)
                .retrieve()
                .body(Map.class);

        if (response == null || response.get("access_token") == null) {
            throw new IllegalStateException("Keycloak token endpoint did not return an access_token");
        }
        return response.get("access_token").toString();
    }

    private static void ensureRunning(final String name, final GenericContainer<?> container) {
        if (!container.isRunning()) {
            throw new IllegalStateException(
                    "%s Testcontainer is not running; the shared E2E environment is invalid".formatted(name)
            );
        }
    }
}
