package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.DBContainerConfig.createPostgreSQLContainer;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

@TestConfiguration(proxyBeanMethods = false)
@EnableConfigurationProperties({ ContainerLogConfig.class, IssuerImageConfig.class, VerifierImageConfig.class })
@Slf4j
public class CompleteEnvironmentTestConfiguration {

    @Bean
    public String tokenDirPath() {
        return "swiyu-softhsm-" + UUID.randomUUID();
    }

    @Bean
    public HsmTokenVolumeCleanup hsmTokenVolumeCleanup(String tokenDirPath) {
        return new HsmTokenVolumeCleanup(tokenDirPath);
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
    public PostgreSQLContainer<?> dbTestContainer(Network network, ContainerLogConfig containerLogConfig) {

        var container = createPostgreSQLContainer(network, containerLogConfig);

        container.start();

        return container;
    }

    @Bean
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
    public IssuerConfig issuerConfig(IssuerImageConfig issuerImageConfig, String tokenDirPath, GenericContainer<?> softHsmContainer) {
        UUID id = UUID.randomUUID();
        return EnvironmentConfig.createIssuerConfig(
                toUri(String.format("https://%s/api/v1/did/%s", MockServerClientConfig.MOCKSERVER_HOST, id)),
                issuerImageConfig.isEnableHsm(),
                issuerImageConfig.isEnableHsm() ? tokenDirPath : null
        );
    }

    @Bean
    public TrustConfig trustConfig(GenericContainer<?> softHsmContainer) {
        UUID id = UUID.randomUUID();
        return EnvironmentConfig.createTrustConfig(toUri(String.format("https://%s/api/v1/did/%s", MockServerClientConfig.MOCKSERVER_HOST, id)));
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
                                               GenericContainer<?> softHsmContainer,
                                               String tokenDirPath,
                                               MockAttestationAuthority mockAttestationAuthority) {

        var imageName = issuerImageConfig.getBaseImage() + ":" + issuerImageConfig.getImageTag();

        var container = IssuerContainerConfig.createIssuerContainer(
                network,
                dbContainer,
                config,
                mockServer,
                imageName,
                issuerImageConfig,
                containerLogConfig,
                tokenDirPath,
                mockAttestationAuthority);

        container.dependsOn(softHsmContainer);
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
            TrustConfig trustConfig,
            MockServerClientConfig mockServerClientConfig,
            MockAttestationAuthority mockAttestationAuthority,
            ContainerLogConfig containerLogConfig) {

        var container = MockServerContainerConfig.createMockServerContainer(network, containerLogConfig);

        container.start();

        mockServerClientConfig.createMockServerClient(container, issuerConfig, trustConfig, mockAttestationAuthority);

        return container;
    }


    @Bean
    public GenericContainer<?> verifierContainer(Network network,
                                                 PostgreSQLContainer<? extends PostgreSQLContainer<?>> dbContainer,
                                                 IssuerConfig config,
                                                 VerifierImageConfig verifierImageConfig,
                                                 GenericContainer<?> softHsmContainer,
                                                 String tokenDirPath,
                                                 ContainerLogConfig containerLogConfig) {

        var imageName = verifierImageConfig.getBaseImage() + ":" + verifierImageConfig.getImageTag();

        var container = VerifierContainerConfig.createVerifierContainer(
                network,
                dbContainer,
                config,
                imageName,
                verifierImageConfig,
                tokenDirPath,
                containerLogConfig
        );

        container.dependsOn(softHsmContainer);
        container.start();

        return container;
    }

    public static final class HsmTokenVolumeCleanup implements DisposableBean {

        private final String tokenVolumeName;

        private HsmTokenVolumeCleanup(String tokenVolumeName) {
            this.tokenVolumeName = tokenVolumeName;
        }

        @Override
        public void destroy() {
            try {
                DockerClientFactory.instance().client().removeVolumeCmd(tokenVolumeName).exec();
            } catch (Exception e) {
                log.warn("Could not remove SoftHSM token volume {}", tokenVolumeName, e);
            }
        }
    }
}
