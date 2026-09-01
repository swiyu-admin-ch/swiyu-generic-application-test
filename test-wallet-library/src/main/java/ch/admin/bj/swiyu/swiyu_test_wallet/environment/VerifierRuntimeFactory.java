package ch.admin.bj.swiyu.swiyu_test_wallet.environment;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.ContainerLogConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ManagementAuthConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.MountableFile;

import java.util.Objects;

/**
 * Assembles and starts one physical Verifier runtime for an explicit logical Verifier identity.
 *
 * <p>Startup registers the logical Verifier with MockServer, starts optional support services, and creates a fresh
 * management client bound to the mapped service URL. The returned handle owns the component container; callers must stop
 * it. A partially started container is stopped before a startup failure is propagated.
 */
public final class VerifierRuntimeFactory {

    private final Network network;
    private final PostgreSQLContainer<?> dbContainer;
    private final ContainerLogConfig containerLogConfig;
    private final MockServerClientConfig mockServerClientConfig;
    private final String tokenDirPath;
    private final EnvironmentSupportServices supportServices;

    public VerifierRuntimeFactory(
            final Network network,
            final PostgreSQLContainer<?> dbContainer,
            final MockServerClientConfig mockServerClientConfig,
            final ContainerLogConfig containerLogConfig,
            final String tokenDirPath,
            final EnvironmentSupportServices supportServices) {
        this.network = network;
        this.dbContainer = dbContainer;
        this.mockServerClientConfig = mockServerClientConfig;
        this.containerLogConfig = containerLogConfig;
        this.tokenDirPath = tokenDirPath;
        this.supportServices = supportServices;
    }

    /**
     * Starts a fully usable Verifier runtime from the supplied request.
     *
     * @return a handle containing the container, management client and runtime configuration
     */
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public VerifierHandle start(final StartRequest request) {
        Objects.requireNonNull(request, "request");
        final VerifierVariant variant = request.variant();
        final ManagementAuthConfig managementAuthConfig = supportServices.managementAuth(variant.requiresKeycloak());
        mockServerClientConfig.registerVerifier(request.config());

        final GenericContainer<?> container = createContainer(request, managementAuthConfig);

        if (variant.requiresHsm()) {
            container.dependsOn(supportServices.softHsm());
        }
        if (variant.requiresKeycloak()) {
            container.dependsOn(supportServices.keycloak());
        }
        try {
            container.start();
            return assembleHandle(request, container, managementAuthConfig);
        } catch (RuntimeException | Error failure) {
            stopAfterFailedStart(container, failure);
            throw failure;
        }
    }

    private GenericContainer<?> createContainer(
            final StartRequest request,
            final ManagementAuthConfig managementAuthConfig) {
        if (request.metadata() == null) {
            return VerifierContainerConfig.createVerifierContainer(
                    network,
                    dbContainer,
                    request.config(),
                    request.imageName(),
                    request.imageConfig(),
                    managementAuthConfig,
                    tokenDirPath,
                    containerLogConfig
            );
        }
        return VerifierContainerConfig.createVerifierContainer(
                network,
                dbContainer,
                request.config(),
                request.imageName(),
                request.imageConfig(),
                managementAuthConfig,
                tokenDirPath,
                containerLogConfig,
                request.metadata()
        );
    }

    private VerifierHandle assembleHandle(
            final StartRequest request,
            final GenericContainer<?> container,
            final ManagementAuthConfig managementAuthConfig) {
        final VerifierManager manager = new VerifierManager(serviceUrl(container));
        final String managementAccessToken = configureManagementAccess(
                request.variant(),
                manager,
                managementAuthConfig
        );
        return new VerifierHandle(
                request.variant(),
                request.config(),
                request.imageConfig(),
                container,
                manager,
                serviceLocation(container),
                managementAuthConfig,
                managementAccessToken
        );
    }

    private String configureManagementAccess(
            final VerifierVariant variant,
            final VerifierManager manager,
            final ManagementAuthConfig managementAuthConfig) {
        if (!variant.requiresKeycloak()) {
            return null;
        }
        final String accessToken = supportServices.verifierManagementAccessToken(managementAuthConfig);
        manager.useBearerToken(accessToken);
        return accessToken;
    }

    private static String serviceUrl(final GenericContainer<?> container) {
        return "http://%s:%d".formatted(container.getHost(), container.getMappedPort(8080));
    }

    private static ServiceLocationContext serviceLocation(final GenericContainer<?> container) {
        return new ServiceLocationContext(container.getHost(), container.getMappedPort(8080).toString());
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

    /**
     * Inputs required to assemble one physical Verifier runtime.
     *
     * @param variant functional flags and optional infrastructure required by this runtime
     * @param config logical Verifier identity reused across a version transition
     * @param imageConfig environment and schema settings for this physical runtime
     * @param imageName exact Docker image name selected for startup
     * @param metadata explicit metadata mount, or {@code null} to use the standard Application Tests fixture
     */
    public record StartRequest(
            VerifierVariant variant,
            VerifierConfig config,
            VerifierImageConfig imageConfig,
            String imageName,
            MountableFile metadata
    ) {

        public StartRequest {
            Objects.requireNonNull(variant, "variant");
            Objects.requireNonNull(config, "config");
            Objects.requireNonNull(imageConfig, "imageConfig");
            if (imageName == null || imageName.isBlank()) {
                throw new IllegalArgumentException("imageName must not be blank");
            }
        }
    }
}
