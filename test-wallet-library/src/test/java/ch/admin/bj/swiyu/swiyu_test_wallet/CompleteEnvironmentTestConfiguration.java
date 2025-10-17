package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.EnvironmentConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import org.mockserver.client.MockServerClient;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.DBContainerConfig.createPostgreSQLContainer;
import static ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig.createMockServerClient;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

@TestConfiguration(proxyBeanMethods = false)
public class CompleteEnvironmentTestConfiguration {

    @Bean
    public IssuerConfig issuerConfig(MockServerContainer mockServer) {
        var id = UUID.randomUUID();
        var mockServerUri = "https://mockserver:1080";
        return EnvironmentConfig.createIssuerConfig(mockServerUri, toUri("%s/api/v1/did/%s".formatted(mockServerUri, id)));
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
                                               MockServerClient mockServerClient) {

        var imageName = issuerImageConfig.getBaseImage() + ":" + issuerImageConfig.getImageTag();

        var container = IssuerContainerConfig.createIssuerContainer(network, dbContainer, config, mockServer, imageName);

        container.start();

        return container;
    }

    @Bean
    public MockServerContainer mockServer(Network network) {

        return MockServerContainerConfig.createAndStartMockServerContainer(network, 1080);
    }

    @Bean
    public MockServerClient mockServerClient(MockServerContainer mockServer, IssuerConfig issuerConfig) {

        return createMockServerClient(mockServer, issuerConfig);
    }


    @Bean
    public GenericContainer<?> verifierContainer(Network network,
                                                 PostgreSQLContainer<? extends PostgreSQLContainer<?>> dbContainer,
                                                 IssuerConfig config,
                                                 VerifierImageConfig verifierImageConfig,
                                                 MockServerClient mockServerClient) {

        var imageName = verifierImageConfig.getBaseImage() + ":" + verifierImageConfig.getImageTag();

        var container = VerifierContainerConfig.createVerifierContainer(network, dbContainer, config, imageName);

        container.start();

        return container;
    }
}
