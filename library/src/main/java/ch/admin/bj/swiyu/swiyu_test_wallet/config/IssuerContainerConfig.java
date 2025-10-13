package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.ContainerUtil.getResourcePath;

@Configuration
public class IssuerContainerConfig {
    public static final String DEFAULT_IMAGE_NAME = "ghcr.io/swiyu-admin-ch/swiyu-issuer:main";

    public static GenericContainer<?> createIssuerContainer(
            Network network,
            PostgreSQLContainer<?> dbContainer,
            IssuerConfig config,
            MockServerContainer mockServer) {

        return new GenericContainer<>(DEFAULT_IMAGE_NAME)
                .withExposedPorts(8080)
                // did:tdw:QmejrSkusQgeM6FfA23L6NPoLy3N8aaiV6X5Ysvb47WSj8:identifier-reg-r.trust-infra.swiyu.admin.ch:api:v1:did:ff8eb859-6996-4e51-a976-be1ca584c124
                .withEnv("ISSUER_ID", config.getIssuerDid())
                .withEnv("TOKEN_TTL", "600")
                .withEnv("OPENID_CONFIG_FILE", "classpath:example_openid.json")
                .withEnv("METADATA_CONFIG_FILE", "file:///tmp/metadata.json")
                .withEnv("EXTERNAL_URL", "http://default-issuer-url.admin.ch")
                .withEnv("DID_SDJWT_VERIFICATION_METHOD", config.getIssuerAssertKeyId())
                .withEnv("OFFER_VALIDITY_SECONDS", "2592000")
                .withEnv("DID_STATUS_LIST_VERIFICATION_METHOD", config.getIssuerAuthKeyId())
                .withEnv("SWIYU_STATUS_REGISTRY_TOKEN_URL", config.getMockServerUri() + "/openid-connect/token")
                .withEnv("SWIYU_STATUS_REGISTRY_API_URL", config.getMockServerUri())
                .withEnv("SWIYU_PARTNER_ID", config.getSwiyuPartnerId())
                .withEnv("SWIYU_STATUS_REGISTRY_CUSTOMER_KEY", "SWIYU_STATUS_REGISTRY_CUSTOMER_KEY")
                .withEnv("SWIYU_STATUS_REGISTRY_CUSTOMER_SECRET", "SWIYU_STATUS_REGISTRY_CUSTOMER_SECRET")
                .withEnv("SWIYU_STATUS_REGISTRY_ACCESS_TOKEN", "SWIYU_STATUS_REGISTRY_ACCESS_TOKEN")
                .withEnv("SWIYU_STATUS_REGISTRY_BOOTSTRAP_REFRESH_TOKEN", "SWIYU_STATUS_REGISTRY_BOOTSTRAP_REFRESH_TOKEN")
                .withEnv("STATUS_LIST_KEY", config.getIssuerAuthKeyPemString())
                .withEnv("SDJWT_KEY", config.getIssuerAssertKeyPemString())
                .withEnv("SPRING_APPLICATION_NAME", "swiyu-demo-issuer-service")
                .withEnv("ENABLE_JWT_AUTH", "false")
                // .withEnv("APPLICATION_VCTMETADATAFILES_DEFAULT", "file:///tmp/vct.json")
                .withEnv("APPLICATION_OVERLAYSCAPTUREARCHITECTUREMETADATAFILES_EXAMPLEOCA", "classpath:example_oca.json")
                .withEnv("APPLICATION_JSONSCHEMAMETADATAFILES_JSONSCHEMA", "classpath:example_json_schema.json")
                .withEnv("POSTGRES_JDBC", DBContainerConfig.getJdbcUrl(dbContainer, DBContainerConfig.ISSUER_DB_SCHEMA))
                .withEnv("POSTGRES_USER", dbContainer.getUsername())
                .withEnv("POSTGRES_PASSWORD", dbContainer.getPassword())
                .withEnv("VERIFICATION_PROOF_TIME_WINDOW_S", "10")
                .withEnv("LOGGING_LEVEL_CH_ADMIN_BJ_SWIYU", "DEBUG")
                .withEnv("LOGGING_LEVEL_CH_ADMIN_BIT_EID", "DEBUG")
                .withEnv("LOGGING_LEVEL_ORG_SPRINGFRAMEWORK_WEB_SERVLET_MVC_SUPPORT", "DEBUG")
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("IssuerContainer")))
                .withNetwork(network)
                .withNetworkAliases("swiyu_issuer")
                .withExtraHost("host.docker.internal", "host-gateway")
                .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("issuer/metadata.json")), "/tmp/metadata.json")
                .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("truststore.jks")), "/app/certs/truststore.jks")
                .withEnv("JAVA_TOOL_OPTIONS", "-Djavax.net.ssl.trustStore=/app/certs/truststore.jks -Djavax.net.ssl.trustStorePassword=changeit")
                .waitingFor(Wait.forLogMessage(".*Started Application.*", 1))
                .dependsOn(dbContainer, mockServer);
    }
}
