package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.experimental.UtilityClass;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.utility.DockerImageName;

@UtilityClass
public class DBContainerConfig {

    public static final String DB_NAME = "swiyu_db";
    public static final String ISSUER_DB_SCHEMA = "swiyu_issuer";
    public static final String VERIFIER_DB_SCHEMA = "swiyu_verifier";

    public static PostgreSQLContainer createPostgreSQLContainer(Network network) {
        return new PostgreSQLContainer<>(
                DockerImageName
                        .parse("postgres:15.14-alpine3.21"))
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger(DB_NAME)))
                .withNetwork(network)
                .withDatabaseName(DB_NAME)
                .withNetworkAliases(DB_NAME);
    }

    public static String getJdbcUrl(PostgreSQLContainer<?> dbContainer, String schema) {
        return String.format("jdbc:postgresql://%s:5432/%s?currentSchema=%s", DB_NAME, dbContainer.getDatabaseName(), schema);
    }

}
