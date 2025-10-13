package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.experimental.UtilityClass;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.ContainerUtil.getResourcePath;

@UtilityClass
public class VerifierContainerConfig {

    public static final String VERIFIER_NAME = "swiyu_verifier";
    public static final String DEFAULT_IMAGE_NAME = "ghcr.io/swiyu-admin-ch/swiyu-verifier:main";

    public static GenericContainer createVerifierContainer(
            Network network,
            PostgreSQLContainer<? extends PostgreSQLContainer<?>> dbContainer,
            IssuerConfig config) {
        return new GenericContainer(DEFAULT_IMAGE_NAME)
                .withExposedPorts(8080)
                .withEnv("VERIFIER_DID", config.getIssuerDid())
                .withEnv("OPENID_CLIENT_METADATA_FILE", "file:///tmp/metadata.json")
                .withEnv("EXTERNAL_URL", "http://default-verifier-url.admin.ch")
                .withEnv("DID_STATUS_LIST_VERIFICATION_METHOD", config.getIssuerAuthKeyId())
                .withEnv("SIGNING_KEY", config.getIssuerAuthKeyPemString())
                .withEnv("APPLICATION_ACCEPTED_STATUS_LIST_HOSTS_0", "mockserver")
                .withEnv("ACCEPTED_STATUS_LIST_HOSTS", config.getMockServerUri())
                .withEnv("client_id_scheme", "did")
                .withEnv("LOGGING_LEVEL_ORG_SPRINGFRAMEWORK_WEB_SERVLET_MVC_SUPPORT", "DEBUG")
                .withEnv("ACCEPTED_STATUS_LIST_HOSTS", "swiyu-demo-verifier-service")
                .withEnv("MANAGEMENT_HEALTH_KUBERNETES_ENABLED", "false")
                .withEnv("MANAGEMENT_INFO_KUBERNETES_ENABLED", "false")
                .withEnv("POSTGRES_JDBC", DBContainerConfig.getJdbcUrl(dbContainer, DBContainerConfig.VERIFIER_DB_SCHEMA))
                .withEnv("POSTGRES_USER", dbContainer.getUsername())
                .withEnv("POSTGRES_PASSWORD", dbContainer.getPassword())
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("VerifierContainer")))
                .withNetwork(network)
                .withNetworkAliases(VERIFIER_NAME)
                .withExtraHost("host.docker.internal", "host-gateway")
                .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("verifier/metadata.json")), "/tmp/metadata.json")
                .waitingFor(Wait.forLogMessage(".*Started Application.*", 1))
                // .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("verifier/cacert.crt")), "/certs-app/cacert.crt")
                .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("truststore.jks")), "/app/certs/truststore.jks")
                .withEnv("JAVA_TOOL_OPTIONS", "-Djavax.net.ssl.trustStore=/app/certs/truststore.jks -Djavax.net.ssl.trustStorePassword=changeit")
                .dependsOn(dbContainer);
    }
}
