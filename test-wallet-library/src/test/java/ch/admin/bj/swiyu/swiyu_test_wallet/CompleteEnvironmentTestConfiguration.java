package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.SwiyuEnvironmentRegistry;
import lombok.extern.slf4j.Slf4j;
import org.mockserver.client.MockServerClient;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.DBContainerConfig.createPostgreSQLContainer;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

@TestConfiguration(proxyBeanMethods = false)
@EnableConfigurationProperties({
        ContainerLogConfig.class,
        IssuerImageConfig.class,
        VerifierImageConfig.class,
        ManagementAuthConfig.class
})
@Slf4j
public class CompleteEnvironmentTestConfiguration {

    private static final Object ENVIRONMENT_LOCK = new Object();

    private static String sharedTokenDirPath;
    private static Network sharedNetwork;
    private static PostgreSQLContainer<?> sharedDbTestContainer;
    private static TrustConfig sharedTrustConfig;
    private static MockAttestationAuthority sharedMockAttestationAuthority;
    private static MockServerClientConfig sharedMockServerClientConfig;
    private static MockServerContainer sharedMockServer;
    private static MockServerClient sharedMockServerClient;
    private static SwiyuEnvironmentRegistry sharedEnvironmentRegistry;
    private static boolean cleanupHookRegistered;

    @Bean
    public String tokenDirPath() {
        synchronized (ENVIRONMENT_LOCK) {
            if (sharedTokenDirPath == null) {
                sharedTokenDirPath = "swiyu-softhsm-" + UUID.randomUUID();
                registerCleanupHook(sharedTokenDirPath);
            }
            return sharedTokenDirPath;
        }
    }

    @Bean
    public HsmTokenVolumeCleanup hsmTokenVolumeCleanup(String tokenDirPath) {
        return new HsmTokenVolumeCleanup(tokenDirPath, false);
    }

    @Bean
    public HSMConfig hsmConfig() {
        return new HSMConfig();
    }

    @Bean(destroyMethod = "")
    public Network network() {
        synchronized (ENVIRONMENT_LOCK) {
            if (sharedNetwork == null) {
                sharedNetwork = Network.newNetwork();
            }
            return sharedNetwork;
        }
    }

    @Bean(destroyMethod = "")
    public PostgreSQLContainer<?> dbTestContainer(Network network, ContainerLogConfig containerLogConfig) {
        synchronized (ENVIRONMENT_LOCK) {
            if (sharedDbTestContainer == null || !sharedDbTestContainer.isRunning()) {
                sharedDbTestContainer = createPostgreSQLContainer(network, containerLogConfig);
                sharedDbTestContainer.start();
                sharedEnvironmentRegistry = null;
            }
            return sharedDbTestContainer;
        }
    }

    @Bean
    public TrustConfig trustConfig() {
        synchronized (ENVIRONMENT_LOCK) {
            if (sharedTrustConfig == null) {
                UUID id = UUID.randomUUID();
                sharedTrustConfig = EnvironmentConfig.createTrustConfig(toUri(String.format("https://%s/api/v1/did/%s", MockServerClientConfig.MOCKSERVER_HOST, id)));
            }
            return sharedTrustConfig;
        }
    }

    @Bean
    public MockAttestationAuthority mockAttestationAuthority() {
        synchronized (ENVIRONMENT_LOCK) {
            if (sharedMockAttestationAuthority == null) {
                UUID id = UUID.randomUUID();
                sharedMockAttestationAuthority = new MockAttestationAuthority(toUri(String.format("https://%s/api/v1/did/%s", MockServerClientConfig.MOCKSERVER_HOST, id)));
            }
            return sharedMockAttestationAuthority;
        }
    }

    @Bean
    public MockServerClientConfig mockServerClientConfig() {
        synchronized (ENVIRONMENT_LOCK) {
            if (sharedMockServerClientConfig == null) {
                sharedMockServerClientConfig = new MockServerClientConfig();
            }
            return sharedMockServerClientConfig;
        }
    }

    @Bean(destroyMethod = "")
    public MockServerContainer mockServer(
            Network network,
            ContainerLogConfig containerLogConfig) {
        synchronized (ENVIRONMENT_LOCK) {
            if (sharedMockServer == null || !sharedMockServer.isRunning()) {
                sharedMockServer = MockServerContainerConfig.createMockServerContainer(network, containerLogConfig);
                sharedMockServer.start();
                sharedMockServerClient = null;
                sharedEnvironmentRegistry = null;
            }
            return sharedMockServer;
        }
    }

    @Bean(destroyMethod = "")
    public MockServerClient mockServerClient(
            MockServerContainer mockServer,
            TrustConfig trustConfig,
            MockServerClientConfig mockServerClientConfig,
            MockAttestationAuthority mockAttestationAuthority) {
        synchronized (ENVIRONMENT_LOCK) {
            if (sharedMockServerClient == null || !mockServer.isRunning()) {
                sharedMockServerClient = mockServerClientConfig.createMockServerClient(mockServer, trustConfig, mockAttestationAuthority);
            }
            return sharedMockServerClient;
        }
    }

    @Bean
    public SwiyuEnvironmentRegistry swiyuEnvironmentRegistry(
            Network network,
            PostgreSQLContainer<?> dbTestContainer,
            MockServerContainer mockServer,
            MockServerClient mockServerClient,
            MockServerClientConfig mockServerClientConfig,
            TrustConfig trustConfig,
            MockAttestationAuthority mockAttestationAuthority,
            ContainerLogConfig containerLogConfig,
            IssuerImageConfig issuerImageConfig,
            VerifierImageConfig verifierImageConfig,
            ManagementAuthConfig managementAuthConfig,
            HSMConfig hsmConfig,
            String tokenDirPath) {
        synchronized (ENVIRONMENT_LOCK) {
            if (sharedEnvironmentRegistry == null) {
                sharedEnvironmentRegistry = new SwiyuEnvironmentRegistry(
                        network,
                        dbTestContainer,
                        mockServer,
                        mockServerClient,
                        mockServerClientConfig,
                        trustConfig,
                        mockAttestationAuthority,
                        containerLogConfig,
                        issuerImageConfig,
                        verifierImageConfig,
                        managementAuthConfig,
                        hsmConfig,
                        tokenDirPath
                );
            }
            return sharedEnvironmentRegistry;
        }
    }

    private static void registerCleanupHook(String tokenDirPath) {
        if (cleanupHookRegistered) {
            return;
        }
        cleanupHookRegistered = true;
        Runtime.getRuntime().addShutdownHook(new Thread(() -> removeHsmTokenVolume(tokenDirPath)));
    }

    private static void removeHsmTokenVolume(String tokenVolumeName) {
        try {
            DockerClientFactory.instance().client().removeVolumeCmd(tokenVolumeName).exec();
        } catch (Exception e) {
            if (e.getMessage() != null && e.getMessage().contains("No such volume")) {
                log.debug("SoftHSM token volume {} was not created", tokenVolumeName);
                return;
            }
            log.warn("Could not remove SoftHSM token volume {}", tokenVolumeName, e);
        }
    }

    public static final class HsmTokenVolumeCleanup implements DisposableBean {

        private final String tokenVolumeName;
        private final boolean enabled;

        private HsmTokenVolumeCleanup(String tokenVolumeName, boolean enabled) {
            this.tokenVolumeName = tokenVolumeName;
            this.enabled = enabled;
        }

        @Override
        public void destroy() {
            if (!enabled) {
                return;
            }
            removeHsmTokenVolume(tokenVolumeName);
        }
    }
}
