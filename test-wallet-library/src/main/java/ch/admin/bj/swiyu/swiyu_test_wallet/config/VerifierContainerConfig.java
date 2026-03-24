package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.support.TestConstants;
import lombok.experimental.UtilityClass;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import java.net.URI;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig.VERIFIER_CALLBACK_PATH;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.ContainerUtil.getResourcePath;

@UtilityClass
public class VerifierContainerConfig {

    @SuppressWarnings("java:S1452") // Testcontainers API requires wildcard return type here
    public static GenericContainer<?> createVerifierContainer(
            Network network,
            PostgreSQLContainer<? extends PostgreSQLContainer<?>> dbContainer,
            IssuerConfig config,
            String imageName,
            VerifierImageConfig verifierImageConfig) {
        try (GenericContainer<?> container = new GenericContainer<>(imageName)) {
            container
                    .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("VerifierContainer")))
                    .withExposedPorts(8080)
                    .withEnv("VERIFIER_DID", config.getIssuerDid())
                    .withEnv("OPENID_CLIENT_METADATA_FILE", "file:///tmp/metadata.json")
                    .withEnv("EXTERNAL_URL", TestConstants.VERIFIER_URL)
                    .withEnv("DID_STATUS_LIST_VERIFICATION_METHOD", config.getIssuerAuthKeyId())
                    .withEnv("SIGNING_KEY", config.getIssuerAuthKeyPemString())
                    .withEnv("APPLICATION_ACCEPTED_STATUS_LIST_HOSTS_0", "mockserver")
                    .withEnv("ACCEPTED_STATUS_LIST_HOSTS", config.getMockServerUri())
                    .withEnv("client_id_scheme", "did")
                    .withEnv("LOGGING_LEVEL_ORG_SPRINGFRAMEWORK_WEB_SERVLET_MVC_SUPPORT", "DEBUG")
                    .withEnv("ACCEPTED_STATUS_LIST_HOSTS", "swiyu-demo-verifier-service")
                    .withEnv("MANAGEMENT_HEALTH_KUBERNETES_ENABLED", "false")
                    .withEnv("MANAGEMENT_INFO_KUBERNETES_ENABLED", "false")
                    .withEnv("POSTGRES_JDBC", DBContainerConfig.getJdbcUrl(dbContainer, verifierImageConfig.getDbSchema()))
                    .withEnv("POSTGRES_USER", dbContainer.getUsername())
                    .withEnv("POSTGRES_PASSWORD", dbContainer.getPassword())
                    .withEnv("POSTGRES_DB_SCHEMA", verifierImageConfig.getDbSchema())
                    .withEnv("WEBHOOK_CALLBACK_URI", URI.create(config.getMockServerUri()).resolve(VERIFIER_CALLBACK_PATH).toString())
                    .withEnv("WEBHOOK_INTERVAL", "100")
                    .withEnv("STATUS_LIST_CACHE_TTL_MILLI", "0")
                    .withNetwork(network)
                    .withNetworkAliases(verifierImageConfig.getNetworkAlias())
                    .withExtraHost("host.docker.internal", "host-gateway")
                    .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("verifier/metadata.json")), "/tmp/metadata.json")
                    .waitingFor(Wait.forLogMessage(".*Started Application.*", 1))
                    .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("truststore.jks")), "/app/certs/truststore.jks")
                    .withEnv("JAVA_TOOL_OPTIONS", "-Djavax.net.ssl.trustStore=/app/certs/truststore.jks -Djavax.net.ssl.trustStorePassword=changeit")
                    .dependsOn(dbContainer);

            return container;
        }
    }
}

