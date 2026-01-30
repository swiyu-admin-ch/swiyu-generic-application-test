package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import lombok.experimental.UtilityClass;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.utility.DockerImageName;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig.createMockServerClient;

@UtilityClass
public class MockServerContainerConfig {

    public static MockServerContainer createAndStartMockServerContainer(Network network, IssuerConfig config) {
        DockerImageName imageName = DockerImageName
                .parse("mockserver/mockserver")
                .withTag("5.15.0");

        var container = new MockServerContainer(imageName)
                .withExposedPorts(1080)
                .withNetwork(network)
                //.withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("mockserver")))
                .withNetworkAliases("mockserver");

        container.start();

        createMockServerClient(container, config);

        return container;
    }
}