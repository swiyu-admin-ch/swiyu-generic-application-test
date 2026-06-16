package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
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

    @Bean
    public String tokenDirPath() {
        return "swiyu-softhsm-" + UUID.randomUUID();
    }

    @Bean
    public HsmTokenVolumeCleanup hsmTokenVolumeCleanup(String tokenDirPath,
                                                       IssuerImageConfig issuerImageConfig,
                                                       VerifierImageConfig verifierImageConfig) {
        return new HsmTokenVolumeCleanup(
                tokenDirPath,
                issuerImageConfig.isEnableHsm() || verifierImageConfig.isEnableHsm()
        );
    }

    @Bean
    public HSMConfig hsmConfig() {
        return new HSMConfig();
    }

    @Bean
    public Network network() {
        return Network.newNetwork();
    }

    @Bean
    @Lazy
    @ConditionalOnProperty(prefix = "application.management-auth", name = "enabled", havingValue = "true")
    public GenericContainer<?> keycloakContainer(Network network,
                                                 ManagementAuthConfig managementAuthConfig) {
        var container = KeycloakContainerConfig.createKeycloakContainer(network, managementAuthConfig);

        container.start();

        return container;
    }

    @Bean
    public PostgreSQLContainer<?> dbTestContainer(Network network, ContainerLogConfig containerLogConfig) {

        var container = createPostgreSQLContainer(network, containerLogConfig);

        container.start();

        return container;
    }

    @Bean
    @Lazy
    public GenericContainer<?> softHsmContainer(
            Network network,
            String tokenDirPath,
            HSMConfig hsmConfig,
            ContainerLogConfig containerLogConfig) {

        var container = HSMContainerConfig.createSoftHsmContainer(network, hsmConfig, tokenDirPath, containerLogConfig);

        container.start();

        return container;
    }

    @Bean
    public IssuerConfig issuerConfig(IssuerImageConfig issuerImageConfig, String tokenDirPath) {
        UUID id = UUID.randomUUID();
        return EnvironmentConfig.createIssuerConfig(
                toUri(String.format("https://%s/api/v1/did/%s", MockServerClientConfig.MOCKSERVER_HOST, id)),
                issuerImageConfig.isEnableHsm(),
                issuerImageConfig.isEnableHsm() ? tokenDirPath : null
        );
    }

    @Bean
    public TrustConfig trustConfig() {
        UUID id = UUID.randomUUID();
        return EnvironmentConfig.createTrustConfig(toUri(String.format("https://%s/api/v1/did/%s", MockServerClientConfig.MOCKSERVER_HOST, id)));
    }

    @Bean
    public VerifierConfig verifierConfig() {
        UUID id = UUID.randomUUID();
        return EnvironmentConfig.createVerifierConfig(toUri(String.format("https://%s/api/v1/did/%s", MockServerClientConfig.MOCKSERVER_HOST, id)));
    }
    @Bean
    public MockAttestationAuthority mockAttestationAuthority() {
        UUID id = UUID.randomUUID();
        return new MockAttestationAuthority(toUri(String.format("https://%s/api/v1/did/%s", MockServerClientConfig.MOCKSERVER_HOST, id)));
    }

    @Bean
    public GenericContainer<?> issuerContainer(Network network,
                                               PostgreSQLContainer<?> dbContainer,
                                               IssuerConfig config,
                                               MockServerContainer mockServer,
                                               IssuerImageConfig issuerImageConfig,
                                               ContainerLogConfig containerLogConfig,
                                               @Qualifier("softHsmContainer") ObjectProvider<GenericContainer<?>> softHsmContainer,
                                               @Qualifier("keycloakContainer") ObjectProvider<GenericContainer<?>> keycloakContainer,
                                               String tokenDirPath,
                                               MockAttestationAuthority mockAttestationAuthority,
                                               ManagementAuthConfig managementAuthConfig) {

        var imageName = issuerImageConfig.getBaseImage() + ":" + issuerImageConfig.getImageTag();

        var container = IssuerContainerConfig.createIssuerContainer(
                network,
                dbContainer,
                config,
                mockServer,
                imageName,
                issuerImageConfig,
                managementAuthConfig,
                containerLogConfig,
                tokenDirPath,
                mockAttestationAuthority);

        if (issuerImageConfig.isEnableHsm()) {
            container.dependsOn(softHsmContainer.getObject());
        }
        if (managementAuthConfig.isEnabled()) {
            container.dependsOn(keycloakContainer.getObject());
        }

        container.start();

        return container;
    }

    @Bean
    public MockServerClientConfig mockServerClientConfig() {
        return new MockServerClientConfig();
    }

    @Bean
    public MockServerContainer mockServer(
            Network network,
            IssuerConfig issuerConfig,
            VerifierConfig verifierConfig,
            TrustConfig trustConfig,
            MockServerClientConfig mockServerClientConfig,
            MockAttestationAuthority mockAttestationAuthority,
            ContainerLogConfig containerLogConfig) {

        var container = MockServerContainerConfig.createMockServerContainer(network, containerLogConfig);

        container.start();

        mockServerClientConfig.createMockServerClient(container, issuerConfig, verifierConfig, trustConfig, mockAttestationAuthority);

        return container;
    }


    @Bean
    public GenericContainer<?> verifierContainer(Network network,
                                                 PostgreSQLContainer<? extends PostgreSQLContainer<?>> dbContainer,
                                                 VerifierConfig config,
                                                 VerifierImageConfig verifierImageConfig,
                                                 @Qualifier("softHsmContainer") ObjectProvider<GenericContainer<?>> softHsmContainer,
                                                 @Qualifier("keycloakContainer") ObjectProvider<GenericContainer<?>> keycloakContainer,
                                                 String tokenDirPath,
                                                 ContainerLogConfig containerLogConfig,
                                                 ManagementAuthConfig managementAuthConfig) {

        var imageName = verifierImageConfig.getBaseImage() + ":" + verifierImageConfig.getImageTag();

        var container = VerifierContainerConfig.createVerifierContainer(
                network,
                dbContainer,
                config,
                imageName,
                verifierImageConfig,
                managementAuthConfig,
                tokenDirPath,
                containerLogConfig
        );

        if (verifierImageConfig.isEnableHsm()) {
            container.dependsOn(softHsmContainer.getObject());
        }
        if (managementAuthConfig.isEnabled()) {
            container.dependsOn(keycloakContainer.getObject());
        }

        container.start();

        return container;
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

            try {
                DockerClientFactory.instance().client().removeVolumeCmd(tokenVolumeName).exec();
            } catch (Exception e) {
                log.warn("Could not remove SoftHSM token volume {}", tokenVolumeName, e);
            }
        }
    }
}
