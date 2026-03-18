package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.support.TestConstants;
import lombok.experimental.UtilityClass;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.*;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import java.net.URI;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig.ISSUER_CALLBACK_PATH;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.ContainerUtil.getResourcePath;

@UtilityClass
public class IssuerContainerConfig {

    @SuppressWarnings("java:S1452") // Testcontainers API requires wildcard return type here
    public static GenericContainer<?> createIssuerContainer(
            final Network network,
            final PostgreSQLContainer<?> dbContainer,
            final IssuerConfig config,
            final MockServerContainer mockServer,
            final String imageName,
            final IssuerImageConfig issuerImageConfig) {
        try (GenericContainer<?> containerBuilder = new GenericContainer<>(imageName)) {
            containerBuilder.withExposedPorts(8080)
                    .withEnv("ISSUER_ID", config.getIssuerDid())
                    .withEnv("TOKEN_TTL", "600")
                    .withEnv("OPENID_CONFIG_FILE", "classpath:example_openid.json")
                    .withEnv("METADATA_CONFIG_FILE", "file:///tmp/metadata.json")
                    .withEnv("EXTERNAL_URL", TestConstants.ISSUER_URL)
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
                    .withEnv("SPRING_APPLICATION_NAME", "swiyu-demo-issuer-service")
                    .withEnv("ENABLE_JWT_AUTH", String.valueOf(issuerImageConfig.isEnableJwtAuth()))
                    .withEnv("ALLOW_REFRESH_TOKEN_ROTATION", "true")
                    .withEnv("RENEWAL_FLOW_ENABLED", "true")
                    .withEnv("BUSINESS_ISSUER_RENEWAL_API_ENDPOINT", config.getMockServerUri() + "/renewal")
                    .withEnv("APPLICATION_OVERLAYSCAPTUREARCHITECTUREMETADATAFILES_EXAMPLEOCA", "classpath:example_oca.json")
                    .withEnv("APPLICATION_JSONSCHEMAMETADATAFILES_JSONSCHEMA", "classpath:example_json_schema.json")
                    .withEnv("POSTGRES_JDBC", DBContainerConfig.getJdbcUrl(dbContainer, issuerImageConfig.getDbSchema()))
                    .withEnv("POSTGRES_USER", dbContainer.getUsername())
                    .withEnv("POSTGRES_PASSWORD", dbContainer.getPassword())
                    .withEnv("POSTGRES_DB_SCHEMA", issuerImageConfig.getDbSchema())
                    .withEnv("VERIFICATION_PROOF_TIME_WINDOW_S", "10")
                    .withEnv("URL_REWRITE_MAPPING", "{\"\":\"\"}")
                    .withEnv("WEBHOOK_CALLBACK_URI", URI.create(config.getMockServerUri()).resolve(
                            ISSUER_CALLBACK_PATH).toString())
                    .withEnv("WEBHOOK_INTERVAL", "10")
                    .withEnv("APPLICATION_DPOP_ENFORCE", String.valueOf(issuerImageConfig.isEnforceDpop()))
                    .withEnv("ENABLE_SIGNED_METADATA", String.valueOf(issuerImageConfig.isSignedMetadata()))
                    .withEnv("APPLICATION_ENCRYPTION_ENFORCE", String.valueOf(issuerImageConfig.isEncryptionEnforce()))
                    .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("IssuerContainer")))
                    .withNetwork(network)
                    .withNetworkAliases(issuerImageConfig.getNetworkAlias())
                    .withExtraHost("host.docker.internal", "host-gateway")
                    .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("issuer/metadata.json")), "/tmp/metadata.json")
                    .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("truststore.jks")), "/app/certs/truststore.jks")
                    .withEnv("JAVA_TOOL_OPTIONS", "-Djavax.net.ssl.trustStore=/app/certs/truststore.jks -Djavax.net.ssl.trustStorePassword=changeit")
                    .waitingFor(Wait.forLogMessage(".*Started Application.*", 1))
                    .dependsOn(dbContainer, mockServer);

            if (issuerImageConfig.isEnableJwtAuth()) {
                var jwtKeyGen = issuerImageConfig.getJwtKeyGenerator();
                containerBuilder.withEnv("JWKS_ALLOWLIST", jwtKeyGen.getJwksAsJson());
            }

            if (issuerImageConfig.isEnableHsm()) {
                containerBuilder
                    .withEnv("SIGNING_KEY_MANAGEMENT_METHOD", "pkcs11")
                    .withEnv("HSM_USER_PIN", issuerImageConfig.getHsmUserPin())
                    .withEnv("HSM_KEY_ID", issuerImageConfig.getHsmKeyId())
                    .withEnv("HSM_KEY_PIN", issuerImageConfig.getHsmKeyPin())
                    .withEnv("HSM_STATUS_KEY_ID", issuerImageConfig.getHsmStatusKeyId())
                    .withEnv("HSM_STATUS_KEY_PIN", issuerImageConfig.getHsmStatusKeyPin())
                    .withEnv("HSM_CONFIG_PATH", "/tmp/pkcs11.cfg")
                    .withEnv("SOFTHSM2_CONF", "/tmp/softhsm2.conf")
                    .withEnv("HSM_TOKEN_DIR", "/tmp/softhsm-tokens")
                    .withEnv("HSM_LIBRARY", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so")
                    .withEnv("HSM_SO_PIN", "1234")
                    .withEnv("HSM_LABEL", issuerImageConfig.getHsmKeyId())
                    .withEnv("HSM_SIGNING_ALGORITHM", "ES256")
                    .withEnv("STATUS_LIST_KEY", "")
                    .withEnv("SDJWT_KEY", "")
                    .withCopyFileToContainer(
                            MountableFile.forClasspathResource("softhsm/libs/libsofthsm2.so", 0755),
                            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
                    )
                    .withCopyFileToContainer(
                            MountableFile.forClasspathResource("softhsm/libs/libopensc.so.8.0.0", 511),
                            "/lib64/libopensc.so.8"
                    )
                    .withCopyFileToContainer(
                            MountableFile.forClasspathResource("softhsm/bins/pkcs11-tool"),
                            "/usr/local/bin/pkcs11-tool"
                    )
                    .withCopyFileToContainer(
                            MountableFile.forClasspathResource("softhsm/bins/softhsm2-util"),
                            "/usr/local/bin/softhsm2-util"
                    )
                    .withCopyFileToContainer(
                        MountableFile.forClasspathResource("softhsm/pkcs11.cfg"),
                        "/tmp/pkcs11.cfg"
                    )
                    .withCopyFileToContainer(
                        MountableFile.forClasspathResource("softhsm/softhsm2.conf"),
                        "/tmp/softhsm2.conf"
                    )
                    .withCopyFileToContainer(
                        MountableFile.forClasspathResource("softhsm/init-hsm.sh"),
                        "/usr/local/bin/init-hsm.sh"
                    )
                    .withCreateContainerCmdModifier(cmd -> cmd.withEntrypoint("/bin/bash", "/usr/local/bin/init-hsm.sh", "app.jar"));
            } else {
                containerBuilder
                    .withEnv("STATUS_LIST_KEY", config.getIssuerAuthKeyPemString())
                    .withEnv("SDJWT_KEY", config.getIssuerAssertKeyPemString());
            }

            return containerBuilder;
        }
    }
}
