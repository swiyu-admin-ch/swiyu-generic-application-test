package ch.admin.bj.swiyu.swiyu_test_wallet.testcontainer;

import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.utility.MountableFile;

import static ch.admin.bj.swiyu.swiyu_test_wallet.testcontainer.ContainerUtil.getResourcePath;

public class MockServerContainer {

    public static GenericContainer<?> getMockServer(Network network) {
        var mockserver = new GenericContainer<>("mockserver/mockserver:5.14.0")
                .withExposedPorts(1080)
                .withNetwork(network)
                .withNetworkAliases("mockserver")
                .withEnv("MOCKSERVER_INITIALIZATION_JSON_PATH", "/config/init.json")
                .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("mockserver/config/init.json")), "/config/init.json")
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("MockServer")));

        mockserver.start();

        return mockserver;
    }
}
