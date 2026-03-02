package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.*;
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
        return EnvironmentConfig.createIssueraConfig(toUri(String.format("https://%s/api/v1/did/%s", MockServerClientConfig.MOCKSERVER_HOST, id)));
    }

    @Bean
    public Network network() {
        return Network.newNetwork();
    }

    @Bean
    public TrustConfig trustConfig() {
        UUID id = UUID.randomUUID();
        return EnvironmentConfig.createTrustConfig(toUri(String.format("https://%s/api/v1/did/%s", MockServerClientConfig.MOCKSERVER_HOST, id)));
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
                                               IssuerImageConfig issuerImageConfig) {

        var imageName = issuerImageConfig.getBaseImage() + ":" + issuerImageConfig.getImageTag();

        var container = IssuerContainerConfig.createIssuerContainer(network, dbContainer, config, mockServer, imageName, issuerImageConfig);

        container.start();

        return container;
    }

    @Bean
    public MockServerClientConfig mockServerClientConfig() {
        return new MockServerClientConfig();
    }

    @Bean
    public MockServerContainer mockServer(Network network, IssuerConfig issuerConfig, TrustConfig trustConfig, MockServerClientConfig mockServerClientConfig) {

        var container = MockServerContainerConfig.createMockServerContainer(network);

        container.start();

        mockServerClientConfig.createMockServerClient(container, issuerConfig, trustConfig);

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