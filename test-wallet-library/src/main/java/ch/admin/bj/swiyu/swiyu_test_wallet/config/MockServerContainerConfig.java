package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.experimental.UtilityClass;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.utility.DockerImageName;

@UtilityClass
public class MockServerContainerConfig {

    public static MockServerContainer createAndStartMockServerContainer(Network network) {
        DockerImageName imageName = DockerImageName
                .parse("mockserver/mockserver")
                .withTag("5.14.0");

        var container = new MockServerContainer(imageName)
                .withExposedPorts(1080)
                .withNetwork(network)
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("mockserver")))
                .withNetworkAliases("mockserver");

        container.start();

        return container;
    }
}
