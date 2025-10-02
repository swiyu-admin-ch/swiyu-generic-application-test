package ch.admin.bj.swiyu.swiyu_test_wallet.testcontainer;

import org.slf4j.LoggerFactory;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.utility.DockerImageName;

public class DBContainer {

    public static final String DB_ALIAS = "default-db";

    public static PostgreSQLContainer<?> startupDbContainer(Network network) {
        var dbContainer = new PostgreSQLContainer<>(
                DockerImageName
                        .parse("docker-hub.nexus.bit.admin.ch/postgres:15.8")
                        .asCompatibleSubstituteFor("postgres:15.8"))
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger(DB_ALIAS)))
                .withNetwork(network)
                .withDatabaseName("swiyu_db")
                .withNetworkAliases(DB_ALIAS);
        dbContainer.start();
        return dbContainer;
    }
}
