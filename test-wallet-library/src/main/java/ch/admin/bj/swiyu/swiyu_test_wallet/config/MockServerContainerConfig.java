package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.experimental.UtilityClass;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import java.time.Duration;

@UtilityClass
public class MockServerContainerConfig {

    public static MockServerContainer createAndStartMockServerContainer(Network network, int port) {
        DockerImageName imageName = DockerImageName
                .parse("mockserver/mockserver")
                .withTag("5.15.0");

        try (MockServerContainer container = new MockServerContainer(imageName)) {
            container.withExposedPorts(port)
                    .withNetwork(network)
                    .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("mockserver")))
                    .withNetworkAliases("mockserver")
                    .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofSeconds(60)));

            container.start();

            return container;
        }
    }
}