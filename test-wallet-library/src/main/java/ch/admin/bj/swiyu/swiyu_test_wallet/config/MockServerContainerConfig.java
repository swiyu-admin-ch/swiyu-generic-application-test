package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.experimental.UtilityClass;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.utility.DockerImageName;

@UtilityClass
public class MockServerContainerConfig {

    public static MockServerContainer createMockServerContainer(Network network, ContainerLogConfig containerLogConfig) {
        MockServerContainer container = new MockServerContainer(
                DockerImageName
                        .parse("mockserver/mockserver")
                        .withTag("7.6.0"));
        container.withExposedPorts(1080);
        container.withNetwork(network);
        container.withEnv(
                "MOCKSERVER_SSL_SUBJECT_ALTERNATIVE_NAME_DOMAINS",
                "localhost,mockserver,untrusted-registry"
        );
        if (containerLogConfig.isMockServer()) {
            container.withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("mockserver")));
        }
        container.withNetworkAliases("mockserver", "untrusted-registry");
        return container;
    }
}
