package ch.admin.bj.swiyu.swiyu_test_wallet.environment;

import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ContainerLogConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ManagementAuthConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockAttestationAuthority;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuanceService;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.MountableFile;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Objects;

/**
 * Assembles and starts one physical Issuer runtime for an explicit logical Issuer identity.
 *
 * <p>Startup registers the logical Issuer with MockServer, starts optional support services, creates management and
 * protocol clients, and mutates {@link IssuerConfig} with the mapped service URL. The returned handle owns the component
 * container; callers must stop it. A partially started container is stopped before a startup failure is propagated.
 */
public final class IssuerRuntimeFactory {

    public static final String KEY_ID = "test-key-1";

    private final Network network;
    private final PostgreSQLContainer<?> dbContainer;
    private final MockServerContainer mockServerContainer;
    private final MockServerClientConfig mockServerClientConfig;
    private final ContainerLogConfig containerLogConfig;
    private final String tokenDirPath;
    private final MockAttestationAuthority mockAttestationAuthority;
    private final EnvironmentSupportServices supportServices;

    public IssuerRuntimeFactory(
            final Network network,
            final PostgreSQLContainer<?> dbContainer,
            final MockServerContainer mockServerContainer,
            final MockServerClientConfig mockServerClientConfig,
            final ContainerLogConfig containerLogConfig,
            final String tokenDirPath,
            final MockAttestationAuthority mockAttestationAuthority,
            final EnvironmentSupportServices supportServices) {
        this.network = network;
        this.dbContainer = dbContainer;
        this.mockServerContainer = mockServerContainer;
        this.mockServerClientConfig = mockServerClientConfig;
        this.containerLogConfig = containerLogConfig;
        this.tokenDirPath = tokenDirPath;
        this.mockAttestationAuthority = mockAttestationAuthority;
        this.supportServices = supportServices;
    }

    /**
     * Starts a fully usable Issuer runtime from the supplied request.
     *
     * @return a handle containing the container, clients, keys and active status list
     */
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public IssuerHandle start(final StartRequest request) {
        Objects.requireNonNull(request, "request");
        final IssuerVariant variant = request.variant();
        final ManagementAuthConfig managementAuthConfig = supportServices.managementAuth(variant.requiresKeycloak());

        mockServerClientConfig.registerIssuer(request.config());
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
            return IssuerContainerConfig.createIssuerContainer(
                    network,
                    dbContainer,
                    request.config(),
                    mockServerContainer,
                    request.imageName(),
                    request.imageConfig(),
                    managementAuthConfig,
                    containerLogConfig,
                    tokenDirPath,
                    mockAttestationAuthority
            );
        }
        return IssuerContainerConfig.createIssuerContainer(
                network,
                dbContainer,
                request.config(),
                mockServerContainer,
                request.imageName(),
                request.imageConfig(),
                managementAuthConfig,
                containerLogConfig,
                tokenDirPath,
                mockAttestationAuthority,
                request.metadata()
        );
    }

    private IssuerHandle assembleHandle(
            final StartRequest request,
            final GenericContainer<?> container,
            final ManagementAuthConfig managementAuthConfig) {
        final IssuerConfig config = request.config();
        final IssuerImageConfig imageConfig = request.imageConfig();
        config.setIssuerServiceUrl(serviceUrl(container));

        final BusinessIssuer manager = new BusinessIssuer(config);
        final String managementAccessToken = configureManagementAccess(
                request.variant(),
                manager,
                managementAuthConfig
        );
        final PrivateKey jwtKey = managementJwtKey(imageConfig);
        manager.onStatusListCreated(statusList -> mockServerClientConfig.setCurrentStatusList(
                config.getIssuerDid(),
                String.valueOf(statusList.getStatusRegistryUrl())
        ));
        final StatusList statusList = request.existingStatusList() == null
                ? createStatusList(manager, jwtKey)
                : manager.useStatusList(request.existingStatusList());

        return new IssuerHandle(
                request.variant(),
                config,
                imageConfig,
                container,
                manager,
                new IssuanceService(config.getIssuerServiceUrl()),
                serviceLocation(container),
                statusList,
                jwtKey,
                jwtKey == null ? null : generateUnauthenticatedJwtKey(),
                KEY_ID,
                managementAuthConfig,
                managementAccessToken
        );
    }

    private String configureManagementAccess(
            final IssuerVariant variant,
            final BusinessIssuer manager,
            final ManagementAuthConfig managementAuthConfig) {
        if (!variant.requiresKeycloak()) {
            return null;
        }
        final String accessToken = supportServices.issuerManagementAccessToken(managementAuthConfig);
        manager.useBearerToken(accessToken);
        return accessToken;
    }

    private static PrivateKey managementJwtKey(final IssuerImageConfig imageConfig) {
        return imageConfig.isEnableJwtAuth() && imageConfig.getJwtKeyGenerator() != null
                ? imageConfig.getJwtKeyGenerator().getPrivateKey()
                : null;
    }

    /** Creates and registers a fresh status list using the runtime's configured management authentication mode. */
    public StatusList createStatusList(final BusinessIssuer manager, final PrivateKey jwtKey) {
        return jwtKey == null
                ? manager.createStatusList(100000, 2)
                : manager.createStatusListWithSignedJwt(jwtKey, KEY_ID, 100000, 2);
    }

    private static PrivateKey generateUnauthenticatedJwtKey() {
        try {
            final KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
            keyPairGen.initialize(new ECGenParameterSpec("secp256r1"));
            return keyPairGen.generateKeyPair().getPrivate();
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Could not generate unauthenticated JWT key", exception);
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

    private static String serviceUrl(final GenericContainer<?> container) {
        return "http://%s:%d".formatted(container.getHost(), container.getMappedPort(8080));
    }

    private static ServiceLocationContext serviceLocation(final GenericContainer<?> container) {
        return new ServiceLocationContext(container.getHost(), container.getMappedPort(8080).toString());
    }

    /**
     * Inputs required to assemble one physical Issuer runtime.
     *
     * @param variant functional flags and optional infrastructure required by this runtime
     * @param config logical Issuer identity reused across a version transition
     * @param imageConfig environment and schema settings for this physical runtime
     * @param imageName exact Docker image name selected for startup
     * @param metadata explicit metadata mount, or {@code null} to use the standard Application Tests fixture
     * @param existingStatusList persisted status list to rebind after an upgrade, or {@code null} to create a new list
     */
    public record StartRequest(
            IssuerVariant variant,
            IssuerConfig config,
            IssuerImageConfig imageConfig,
            String imageName,
            MountableFile metadata,
            StatusList existingStatusList
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
