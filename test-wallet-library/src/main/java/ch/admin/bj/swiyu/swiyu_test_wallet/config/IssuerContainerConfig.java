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
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig.ISSUER_CALLBACK_PATH;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.ContainerUtil.getResourcePath;

@UtilityClass
public class IssuerContainerConfig {

    private static final Duration STARTUP_TIMEOUT = Duration.ofMinutes(3);
    private static final String DATASOURCE_MAXIMUM_POOL_SIZE = "5";
    private static final String DATASOURCE_MINIMUM_IDLE = "1";

    /** Builds an Issuer container using the standard Application Tests metadata fixture without starting it. */
    @SuppressWarnings("java:S1452") // Testcontainers API requires wildcard return type here
    public static GenericContainer<?> createIssuerContainer(
            final Network network,
            final PostgreSQLContainer<?> dbContainer,
            final IssuerConfig config,
            final MockServerContainer mockServer,
            final String imageName,
            final IssuerImageConfig issuerImageConfig,
            final ManagementAuthConfig managementAuthConfig,
            final ContainerLogConfig containerLogConfig,
            final String tokenDirPath,
            final MockAttestationAuthority mockAttestationAuthority) {
        return createIssuerContainer(
                network,
                dbContainer,
                config,
                mockServer,
                imageName,
                issuerImageConfig,
                managementAuthConfig,
                containerLogConfig,
                tokenDirPath,
                mockAttestationAuthority,
                MountableFile.forHostPath(getResourcePath("issuer/metadata.json"))
        );
    }

    /**
     * Builds an Issuer container with an explicit metadata source mounted at {@code /tmp/metadata.json}.
     *
     * <p>The returned container is configured but not started; its caller owns the runtime lifecycle.
     */
    @SuppressWarnings("java:S1452") // Testcontainers API requires wildcard return type here
    public static GenericContainer<?> createIssuerContainer(
            final Network network,
            final PostgreSQLContainer<?> dbContainer,
            final IssuerConfig config,
            final MockServerContainer mockServer,
            final String imageName,
            final IssuerImageConfig issuerImageConfig,
            final ManagementAuthConfig managementAuthConfig,
            final ContainerLogConfig containerLogConfig,
            final String tokenDirPath,
            final MockAttestationAuthority mockAttestationAuthority,
            final MountableFile metadata) {
        GenericContainer<?> containerBuilder = new GenericContainer<>(imageName);
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
                    .withEnv("SWIYU_TRUST_REGISTRY_API_URL", config.getMockServerUri())
                    .withEnv("APPLICATION_ACCEPTED_REGISTRY_HOSTS_0", "mockserver")
                    .withEnv("SWIYU_PARTNER_ID", config.getSwiyuPartnerId())
                    .withEnv("SWIYU_STATUS_REGISTRY_CUSTOMER_KEY", "SWIYU_STATUS_REGISTRY_CUSTOMER_KEY")
                    .withEnv("SWIYU_STATUS_REGISTRY_CUSTOMER_SECRET", "SWIYU_STATUS_REGISTRY_CUSTOMER_SECRET")
                    .withEnv("SWIYU_STATUS_REGISTRY_ACCESS_TOKEN", "SWIYU_STATUS_REGISTRY_ACCESS_TOKEN")
                    .withEnv("SWIYU_STATUS_REGISTRY_BOOTSTRAP_REFRESH_TOKEN", "SWIYU_STATUS_REGISTRY_BOOTSTRAP_REFRESH_TOKEN")
                    .withEnv("SWIYU_TRUST_REGISTRY_MAX_CACHE_SIZE",
                            String.valueOf(issuerImageConfig.getTrustRegistryMaxCacheSize()))
                    .withEnv("SWIYU_TRUST_REGISTRY_MAX_CACHE_TTL_SECONDS",
                            String.valueOf(issuerImageConfig.getTrustRegistryMaxCacheTtlSeconds()))
                    .withEnv("SWIYU_TRUST_REGISTRY_CLOCK_SKEW_BUFFER_SECONDS",
                            String.valueOf(issuerImageConfig.getTrustRegistryClockSkewBufferSeconds()))
                    .withEnv("SPRING_APPLICATION_NAME", "swiyu-demo-issuer-service")
                    .withEnv("ENABLE_JWT_AUTH", String.valueOf(issuerImageConfig.isEnableJwtAuth()))
                    .withEnv("ALLOW_REFRESH_TOKEN_ROTATION", "true")
                    .withEnv("RENEWAL_FLOW_ENABLED", "true")
                    .withEnv("BUSINESS_ISSUER_RENEWAL_API_ENDPOINT",
                            config.getMockServerUri() + "/renewal?issuerDid=" + config.getIssuerDid())
                    .withEnv("APPLICATION_OVERLAYSCAPTUREARCHITECTUREMETADATAFILES_EXAMPLEOCA", "classpath:example_oca.json")
                    .withEnv("APPLICATION_JSONSCHEMAMETADATAFILES_JSONSCHEMA", "classpath:example_json_schema.json")
                    .withEnv("POSTGRES_JDBC", DBContainerConfig.getJdbcUrl(dbContainer, issuerImageConfig.getDbSchema()))
                    .withEnv("POSTGRES_USER", dbContainer.getUsername())
                    .withEnv("POSTGRES_PASSWORD", dbContainer.getPassword())
                    .withEnv("POSTGRES_DB_SCHEMA", issuerImageConfig.getDbSchema())
                    .withEnv("SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE", DATASOURCE_MAXIMUM_POOL_SIZE)
                    .withEnv("SPRING_DATASOURCE_HIKARI_MINIMUM_IDLE", DATASOURCE_MINIMUM_IDLE)
                    .withEnv("VERIFICATION_PROOF_TIME_WINDOW_S", "10")
                    .withEnv("URL_REWRITE_MAPPING", "{\"\":\"\"}")
                    .withEnv("WEBHOOK_CALLBACK_URI", URI.create(config.getMockServerUri()).resolve(
                            ISSUER_CALLBACK_PATH).toString())
                    .withEnv("WEBHOOK_INTERVAL", "10")
                    .withEnv("APPLICATION_DPOP_ENFORCE", String.valueOf(issuerImageConfig.isEnforceDpop()))
                    .withEnv("ENABLE_SIGNED_METADATA", String.valueOf(issuerImageConfig.isSignedMetadata()))
                    .withEnv("RECURSIVE_DISCLOSURE_ENABLED", String.valueOf(true))
                    .withEnv("APPLICATION_ENCRYPTION_ENFORCE", String.valueOf(issuerImageConfig.isEncryptionEnforce()))
                    .withNetwork(network)
                    .withNetworkAliases(issuerImageConfig.getNetworkAlias())
                    .withExtraHost("host.docker.internal", "host-gateway")
                    .withCopyFileToContainer(metadata, "/tmp/metadata.json")
                    .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("truststore.jks")), "/app/certs/truststore.jks")
                    .withEnv("JAVA_TOOL_OPTIONS", "-Djavax.net.ssl.trustStore=/app/certs/truststore.jks -Djavax.net.ssl.trustStorePassword=changeit")
                    .withEnv(
                            "APPLICATION_TRUSTED_ATTESTATION_PROVIDERS",
                            mockAttestationAuthority.getDid()
                    )
                    .waitingFor(Wait.forLogMessage(".*Started Application.*", 1).withStartupTimeout(STARTUP_TIMEOUT))
                    .dependsOn(dbContainer, mockServer);

            if (containerLogConfig.isIssuer()) {
                containerBuilder.withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("IssuerContainer")));
            }

            if (issuerImageConfig.isEnableJwtAuth()) {
                var jwtKeyGen = issuerImageConfig.getJwtKeyGenerator();
                containerBuilder.withEnv("JWKS_ALLOWLIST", jwtKeyGen.getJwksAsJson());
            }

            if (issuerImageConfig.isMultipleSigningKeys()) {
                configureMultipleSigningKeys(containerBuilder, config);
            }

            if (managementAuthConfig.isEnabled()) {
                containerBuilder
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

            if (issuerImageConfig.isEnableHsm()) {
                containerBuilder
                        .withEnv("SIGNING_KEY_MANAGEMENT_METHOD", HSMConfig.SIGNING_KEY_METHOD)
                        .withEnv("HSM_USER", issuerImageConfig.getHsmUser())
                        .withEnv("HSM_PASSWORD", issuerImageConfig.getHsmPassword())
                        .withEnv("HSM_USER_PIN", issuerImageConfig.getHsmUserPin())
                        .withEnv("HSM_LABEL", issuerImageConfig.getHsmKeyId())
                        .withEnv("HSM_KEY_ID", issuerImageConfig.getHsmKeyId())
                        .withEnv("HSM_KEY_PIN", issuerImageConfig.getHsmKeyPin())
                        .withEnv("HSM_STATUS_KEY_ID", issuerImageConfig.getHsmStatusKeyId())
                        .withEnv("HSM_STATUS_KEY_PIN", issuerImageConfig.getHsmStatusKeyPin())
                        .withEnv("HSM_CONFIG_PATH", HSMConfig.PKCS11_CFG)
                        .withEnv("SOFTHSM2_CONF", HSMConfig.SOFTHSM_CONF)
                        .withEnv("HSM_TOKEN_DIR", HSMConfig.TOKEN_DIR)
                        .withEnv("HSM_LIBRARY", HSMConfig.LIB_PATH)
                        .withEnv("STATUS_LIST_KEY", "")
                        .withEnv("SDJWT_KEY", "");

                HSMConfig.FILES.forEach(file ->
                        containerBuilder.withCopyFileToContainer(
                                MountableFile.forClasspathResource((String) file[0], (int) file[2]),
                                (String) file[1]
                        )
                );

                HSMContainerConfig.withTokenVolume(containerBuilder, tokenDirPath);
            } else {
                containerBuilder
                    .withEnv("STATUS_LIST_KEY", config.getIssuerAuthKeyPemString())
                    .withEnv("SDJWT_KEY", config.getIssuerAssertKeyPemString());
            }

        return containerBuilder;
    }

    private static void configureMultipleSigningKeys(
            final GenericContainer<?> container,
            final IssuerConfig primaryIdentity) {
        final List<IssuerConfig> identities = new ArrayList<>();
        identities.add(primaryIdentity);
        identities.addAll(primaryIdentity.getAdditionalSigningIdentities());

        for (int index = 0; index < identities.size(); index++) {
            final IssuerConfig identity = identities.get(index);
            final String sdJwtPrefix = "APPLICATION_KEY_SDJWT_SIGNINGKEYS_%d_".formatted(index);
            final String statusListPrefix = "APPLICATION_STATUSLIST_SIGNINGKEYS_%d_".formatted(index);

            container
                    .withEnv(sdJwtPrefix + "VERIFICATIONMETHOD", identity.getIssuerAssertKeyId())
                    .withEnv(sdJwtPrefix + "PRIVATEKEY", identity.getIssuerAssertKeyPemString())
                    .withEnv(statusListPrefix + "VERIFICATIONMETHOD", identity.getIssuerAuthKeyId())
                    .withEnv(statusListPrefix + "PRIVATEKEY", identity.getIssuerAuthKeyPemString());
        }
    }
}
