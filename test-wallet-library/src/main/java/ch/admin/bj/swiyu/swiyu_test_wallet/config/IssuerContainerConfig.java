package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import lombok.experimental.UtilityClass;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.ContainerUtil.getResourcePath;

@UtilityClass
public class IssuerContainerConfig {

    public static GenericContainer<?> createIssuerContainer(
            final Network network,
            final PostgreSQLContainer<?> dbContainer,
            final IssuerConfig config,
            final MockServerContainer mockServer,
            final String imageName,
            final IssuerImageConfig issuerImageConfig) {

        return new GenericContainer<>(imageName)
                .withExposedPorts(8080)
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
                .withEnv("ENABLE_SIGNED_METADATA", "true")
                .withEnv("RENEWAL_FLOW_ENABLED", "true")
                .withEnv("BUSINESS_ISSUER_RENEWAL_API_ENDPOINT", config.getMockServerUri() + "/renewal")
                .withEnv("APPLICATION_OVERLAYSCAPTUREARCHITECTUREMETADATAFILES_EXAMPLEOCA", "classpath:example_oca.json")
                .withEnv("APPLICATION_JSONSCHEMAMETADATAFILES_JSONSCHEMA", "classpath:example_json_schema.json")
                .withEnv("POSTGRES_JDBC", DBContainerConfig.getJdbcUrl(dbContainer, issuerImageConfig.getDbSchema()))
                .withEnv("POSTGRES_USER", dbContainer.getUsername())
                .withEnv("POSTGRES_PASSWORD", dbContainer.getPassword())
                .withEnv("VERIFICATION_PROOF_TIME_WINDOW_S", "10")
                .withEnv("URL_REWRITE_MAPPING", "{\"\":\"\"}")
                .withEnv("WEBHOOK_CALLBACK_URI", config.getMockServerUri() + "/callback")
                .withEnv("WEBHOOK_INTERVAL", "100")
                //.withEnv("APPLICATION_DPOP_ENFORCE", "true")
                .withEnv("APPLICATION_DPOP_ENFORCE", String.valueOf(issuerImageConfig.isEnforceDpop()))
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("IssuerContainer")))
                .withNetwork(network)
                .withNetworkAliases(issuerImageConfig.getNetworkAlias())
                .withExtraHost("host.docker.internal", "host-gateway")
                .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("issuer/metadata.json")), "/tmp/metadata.json")
                .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("truststore.jks")), "/app/certs/truststore.jks")
                .withEnv("JAVA_TOOL_OPTIONS", "-Djavax.net.ssl.trustStore=/app/certs/truststore.jks -Djavax.net.ssl.trustStorePassword=changeit")
                .waitingFor(Wait.forLogMessage(".*Started Application.*", 1))
                .dependsOn(dbContainer, mockServer);
    }
}
