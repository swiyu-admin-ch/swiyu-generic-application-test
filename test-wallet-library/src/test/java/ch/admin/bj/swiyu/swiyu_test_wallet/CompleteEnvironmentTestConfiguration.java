package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.EnvironmentConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SoftHsmContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SoftHsmImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.DBContainerConfig.createPostgreSQLContainer;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

@TestConfiguration(proxyBeanMethods = false)
@EnableConfigurationProperties({ IssuerImageConfig.class, VerifierImageConfig.class, SoftHsmImageConfig.class })
public class CompleteEnvironmentTestConfiguration {

    @Bean
    public IssuerConfig issuerConfig() {
        UUID id = UUID.randomUUID();
        return EnvironmentConfig.createIssueraConfig(toUri("https://mockserver:1080/api/v1/did/" + id));
    }

    @Bean
    public Network network() {
        return Network.newNetwork();
    }

    @Bean
    public PostgreSQLContainer<?> dbTestContainer(Network network) {

        var container = createPostgreSQLContainer(network);

        container.start();

        return container;
    }

    @Bean
    public GenericContainer<?> issuerContainer(Network network,
                                               PostgreSQLContainer<?> dbContainer,
                                               IssuerConfig config,
                                               MockServerContainer mockServer,
                                               IssuerImageConfig issuerImageConfig,
                                               GenericContainer<?> softHsmContainer) {

        var imageName = issuerImageConfig.getBaseImage() + ":" + issuerImageConfig.getImageTag();

        var container = IssuerContainerConfig.createIssuerContainer(network, dbContainer, config, mockServer, imageName, issuerImageConfig);

        container.dependsOn(softHsmContainer);
        container.start();

        return container;
    }

    @Bean
    public MockServerClientConfig mockServerClientConfig() {
        return new MockServerClientConfig();
    }

    @Bean
    public MockServerContainer mockServer(Network network, IssuerConfig issuerConfig, MockServerClientConfig mockServerClientConfig) {

        var container = MockServerContainerConfig.createMockServerContainer(network);

        container.start();

        mockServerClientConfig.createMockServerClient(container, issuerConfig);

        return container;
    }


    @Bean
    public GenericContainer<?> verifierContainer(Network network,
                                                 PostgreSQLContainer<? extends PostgreSQLContainer<?>> dbContainer,
                                                 IssuerConfig config,
                                                 VerifierImageConfig verifierImageConfig) {

        var imageName = verifierImageConfig.getBaseImage() + ":" + verifierImageConfig.getImageTag();

        var container = VerifierContainerConfig.createVerifierContainer(network, dbContainer, config, imageName, verifierImageConfig);

        container.start();

        return container;
    }

    @Bean
    public GenericContainer<?> softHsmContainer(Network network, SoftHsmImageConfig softHsmImageConfig) {

        var container = SoftHsmContainerConfig.createSoftHsmContainer(network, softHsmImageConfig);

        container.start();

        return container;
    }
}