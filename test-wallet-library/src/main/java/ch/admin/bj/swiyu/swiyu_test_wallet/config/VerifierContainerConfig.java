package ch.admin.bj.swiyu.swiyu_test_wallet.config;

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
import java.time.Duration;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig.VERIFIER_CALLBACK_PATH;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.ContainerUtil.getResourcePath;

@UtilityClass
public class VerifierContainerConfig {

    private static final String MOCKSERVER_HTTPS_URL = "https://" + MockServerClientConfig.MOCKSERVER_HOST;
    private static final String MOCKSERVER_HTTP_URL = "http://" + MockServerClientConfig.MOCKSERVER_HOST;
    private static final String MOCKSERVER_URL_REWRITE_MAPPING =
            "{\"%s\":\"%s\"}".formatted(MOCKSERVER_HTTPS_URL, MOCKSERVER_HTTP_URL);
    private static final Duration STARTUP_TIMEOUT = Duration.ofMinutes(3);

    @SuppressWarnings("java:S1452") // Testcontainers API requires wildcard return type here
    public static GenericContainer<?> createVerifierContainer(
            Network network,
            PostgreSQLContainer<?> dbContainer,
            VerifierConfig config,
            String imageName,
            VerifierImageConfig verifierImageConfig,
            ManagementAuthConfig managementAuthConfig,
            String tokenDirPath,
            ContainerLogConfig containerLogConfig) {
        GenericContainer<?> container = new GenericContainer<>(imageName);
        container
                    .withExposedPorts(8080)
                    .withEnv("VERIFIER_DID", config.getVerifierDid())
                    .withEnv("OPENID_CLIENT_METADATA_FILE", "file:///tmp/metadata.json")
                    .withEnv("EXTERNAL_URL", TestConstants.VERIFIER_URL)
                    .withEnv("DID_VERIFICATION_METHOD", config.getVerifierAuthKeyId())
                    .withEnv("DID_STATUS_LIST_VERIFICATION_METHOD", config.getVerifierAuthKeyId())
                    .withEnv("SIGNING_KEY", config.getVerifierAuthKeyPemString())
                    .withEnv("APPLICATION_ACCEPTED_REGISTRY_HOSTS_0", "mockserver")
                    .withEnv("APPLICATION_ACCEPTED_STATUS_LIST_HOSTS_0", "mockserver")
                    .withEnv("APPLICATION_CLIENT_ID_PREFIX", "decentralized_identifier")
                    .withEnv("URL_REWRITE_MAPPING", MOCKSERVER_URL_REWRITE_MAPPING)
                    .withEnv("SWIYU_TRUST_REGISTRY_API_URL", config.getMockServerUri())
                    .withEnv("SWIYU_TRUST_REGISTRY_CUSTOMER_KEY", "SWIYU_TRUST_REGISTRY_CUSTOMER_KEY")
                    .withEnv("SWIYU_TRUST_REGISTRY_CUSTOMER_SECRET", "SWIYU_TRUST_REGISTRY_CUSTOMER_SECRET")
                    .withEnv("SWIYU_TRUST_REGISTRY_MAX_CACHE_TTL_SECONDS", "10000")
                    .withEnv("SWIYU_TMS_AUTHORING_URL", config.getMockServerUri())
                    .withEnv("SWIYU_TMS_OAUTH_TOKEN_URL", config.getMockServerUri() + "/openid-connect/token")
                    .withEnv("SWIYU_TMS_OAUTH_CLIENT_ID", "SWIYU_TRUST_REGISTRY_CUSTOMER_KEY")
                    .withEnv("SWIYU_TMS_OAUTH_CLIENT_SECRET", "SWIYU_TRUST_REGISTRY_CUSTOMER_SECRET")
                    .withEnv("SWIYU_TMS_BOOTSTRAP_REFRESH_TOKEN", "SWIYU_TMS_BOOTSTRAP_REFRESH_TOKEN")
                    .withEnv("client_id_scheme", "did")
                    .withEnv("LOGGING_LEVEL_ORG_SPRINGFRAMEWORK_WEB_SERVLET_MVC_SUPPORT", "DEBUG")
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
                    .waitingFor(Wait.forLogMessage(".*Started Application.*", 1).withStartupTimeout(STARTUP_TIMEOUT))
                    .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("truststore.jks")), "/app/certs/truststore.jks")
                    .withEnv("JAVA_TOOL_OPTIONS", "-Djavax.net.ssl.trustStore=/app/certs/truststore.jks -Djavax.net.ssl.trustStorePassword=changeit")
                    .dependsOn(dbContainer);

            if (containerLogConfig.isVerifier()) {
                container.withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("VerifierContainer")));
            }

            if (managementAuthConfig.isEnabled()) {
                container
                        .withEnv("SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_ISSUERURI",
                                managementAuthConfig.getContainerIssuerUri())
                        .withEnv("SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_ISSUER_URI",
                                managementAuthConfig.getContainerIssuerUri())
                        .withEnv("SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_JWKSETURI",
                                managementAuthConfig.getContainerJwkSetUri())
                        .withEnv("SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_JWK_SET_URI",
                                managementAuthConfig.getContainerJwkSetUri())
                        .withEnv("SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_JWSALGORITHMS",
                                managementAuthConfig.getJwsAlgorithms())
                        .withEnv("SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_JWS_ALGORITHMS",
                                managementAuthConfig.getJwsAlgorithms());
            }

            if (verifierImageConfig.isEnableHsm()) {
                container
                        .withEnv("SIGNING_KEY_MANAGEMENT_METHOD", HSMConfig.SIGNING_KEY_METHOD)
                        .withEnv("HSM_USER", verifierImageConfig.getHsmUser())
                        .withEnv("HSM_PASSWORD", verifierImageConfig.getHsmPassword())
                        .withEnv("HSM_USER_PIN", verifierImageConfig.getHsmUserPin())
                        .withEnv("HSM_KEY_ID", verifierImageConfig.getHsmKeyId())
                        .withEnv("HSM_KEY_PIN", verifierImageConfig.getHsmKeyPin())
                        .withEnv("HSM_CONFIG_PATH", HSMConfig.PKCS11_CFG)
                        .withEnv("SOFTHSM2_CONF", HSMConfig.SOFTHSM_CONF)
                        .withEnv("HSM_TOKEN_DIR", HSMConfig.TOKEN_DIR)
                        .withEnv("HSM_LIBRARY", HSMConfig.LIB_PATH);

                HSMConfig.FILES.forEach(file ->
                        container.withCopyFileToContainer(
                                MountableFile.forClasspathResource((String) file[0], (int) file[2]),
                                (String) file[1]
                        )
                );

                HSMContainerConfig.withTokenVolume(container, tokenDirPath);
            }

        return container;
    }
}
