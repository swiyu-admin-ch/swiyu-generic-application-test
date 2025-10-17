package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.EnvironmentConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.DBContainerConfig.createPostgreSQLContainer;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

@TestConfiguration(proxyBeanMethods = false)
@Profile("!external")
public class CompleteEnvironmentTestConfiguration {

    @Autowired
    IssuerImageConfig issuerImageConfig;
    @Autowired
    VerifierImageConfig verifierImageConfig;

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
                                               MockServerContainer mockServer) {

        var imageName = issuerImageConfig.getBaseImage() + ":" + issuerImageConfig.getImageTag();

        var container = IssuerContainerConfig.createIssuerContainer(network, dbContainer, config, mockServer, imageName);

        container.start();

        return container;
    }

    @Bean
    public MockServerContainer mockServer(Network network, IssuerConfig issuerConfig) {

        return MockServerContainerConfig.createAndStartMockServerContainer(network, issuerConfig);
    }


    @Bean
    public GenericContainer<?> verifierContainer(Network network,
                                                 PostgreSQLContainer<? extends PostgreSQLContainer<?>> dbContainer,
                                                 IssuerConfig config) {

        var imageName = verifierImageConfig.getBaseImage() + ":" + verifierImageConfig.getImageTag();

        var container = VerifierContainerConfig.createVerifierContainer(network, dbContainer, config, imageName);

        container.start();

        return container;
    }
}
