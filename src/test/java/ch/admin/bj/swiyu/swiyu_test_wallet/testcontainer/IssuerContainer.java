package ch.admin.bj.swiyu.swiyu_test_wallet.testcontainer;

import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import static ch.admin.bj.swiyu.swiyu_test_wallet.testcontainer.ContainerUtil.getResourcePath;
import static ch.admin.bj.swiyu.swiyu_test_wallet.testcontainer.DBContainer.DB_ALIAS;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

public class IssuerContainer {

    public static GenericContainer<?> getIssuerContainer(Network network, PostgreSQLContainer<?> dbContainer) {

        var imageName = "ghcr.io/swiyu-admin-ch/swiyu-issuer:main";

        var mockServerTest = "mockserver%3A1080";
        var mockServerUri = toUri("https://%s:%s".formatted("mockserver", 1080)).toString();
        var jdbcUrl = String.format("jdbc:postgresql://%s:5432/%s?currentSchema=%s", DB_ALIAS, dbContainer.getDatabaseName(), "swiyu_issuer");
        var swiyuPartnerId = "83c5a86c-3549-495b-bb90-e968b2157b17";



        var issuer = new GenericContainer<>(imageName)
                .withExposedPorts(8080)
                // did:tdw:QmejrSkusQgeM6FfA23L6NPoLy3N8aaiV6X5Ysvb47WSj8:identifier-reg-r.trust-infra.swiyu.admin.ch:api:v1:did:ff8eb859-6996-4e51-a976-be1ca584c124
                .withEnv("ISSUER_ID", "did:tdw:Qmeqe1d1tRTCLg5Z4mVUrqhCRbvtHBBpDYTsirnJBt5UXC:" + mockServerTest + ":api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085")
                .withEnv("TOKEN_TTL", "600")
                .withEnv("OPENID_CONFIG_FILE", "classpath:example_openid.json")
                .withEnv("METADATA_CONFIG_FILE", "file:///tmp/metadata.json")
                .withEnv("EXTERNAL_URL", "http://default-issuer-url.admin.ch")
                .withEnv("DID_SDJWT_VERIFICATION_METHOD", "did:tdw:Qmeqe1d1tRTCLg5Z4mVUrqhCRbvtHBBpDYTsirnJBt5UXC:" + mockServerTest + ":api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01")
                .withEnv("OFFER_VALIDITY_SECONDS", "2592000")
                .withEnv("DID_STATUS_LIST_VERIFICATION_METHOD", "did:tdw:Qmeqe1d1tRTCLg5Z4mVUrqhCRbvtHBBpDYTsirnJBt5UXC:" + mockServerTest + ":api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01")
                .withEnv("SWIYU_STATUS_REGISTRY_TOKEN_URL", mockServerUri + "/openid-connect/token")
                .withEnv("SWIYU_STATUS_REGISTRY_API_URL", mockServerUri)
                .withEnv("SWIYU_PARTNER_ID", swiyuPartnerId)
                .withEnv("SWIYU_STATUS_REGISTRY_CUSTOMER_KEY", "SWIYU_STATUS_REGISTRY_CUSTOMER_KEY")
                .withEnv("SWIYU_STATUS_REGISTRY_CUSTOMER_SECRET", "SWIYU_STATUS_REGISTRY_CUSTOMER_SECRET")
                .withEnv("SWIYU_STATUS_REGISTRY_ACCESS_TOKEN", "SWIYU_STATUS_REGISTRY_ACCESS_TOKEN")
                .withEnv("SWIYU_STATUS_REGISTRY_BOOTSTRAP_REFRESH_TOKEN", "SWIYU_STATUS_REGISTRY_BOOTSTRAP_REFRESH_TOKEN")
                .withEnv("STATUS_LIST_KEY", "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBEuQQO9ccMGC+sI4N/yZDcckud+/Q1fsvI5LN5Sk+9eoAoGCCqGSM49\nAwEHoUQDQgAEiBVeBG3/btA3mDyPB6zwPaHlNm87soVKP1abZjqMzdeOihDosLVJ\nL/lC/dWkK1Xj5gXHbWXNCqQhkBw9QwDvXA==\n-----END EC PRIVATE KEY-----")
                .withEnv("SDJWT_KEY", "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBEuQQO9ccMGC+sI4N/yZDcckud+/Q1fsvI5LN5Sk+9eoAoGCCqGSM49\nAwEHoUQDQgAEiBVeBG3/btA3mDyPB6zwPaHlNm87soVKP1abZjqMzdeOihDosLVJ\nL/lC/dWkK1Xj5gXHbWXNCqQhkBw9QwDvXA==\n-----END EC PRIVATE KEY-----")
                .withEnv("LOGGING_LEVEL_CH_ADMIN_BIT_EID", "DEBUG")
                .withEnv("LOGGING_LEVEL_ORG_SPRINGFRAMEWORK_WEB_SERVLET_MVC_SUPPORT", "DEBUG")
                .withEnv("SPRING_APPLICATION_NAME", "swiyu-demo-issuer-service")
                .withEnv("ENABLE_JWT_AUTH", "false")
                .withEnv("APPLICATION_VCTMETADATAFILES_DEFAULT", "file:///tmp/vct.json")
                .withEnv("APPLICATION_OVERLAYSCAPTUREARCHITECTUREMETADATAFILES_EXAMPLEOCA", "classpath:example_oca.json")
                .withEnv("APPLICATION_JSONSCHEMAMETADATAFILES_JSONSCHEMA", "classpath:example_json_schema.json")
                .withEnv("POSTGRES_JDBC", jdbcUrl)
                .withEnv("POSTGRES_USER", dbContainer.getUsername())
                .withEnv("POSTGRES_PASSWORD", dbContainer.getPassword())
                .withEnv("VERIFICATION_PROOF_TIME_WINDOW_S", "10")
                .withEnv("LOGGING_LEVEL_CH_ADMIN_BJ_SWIYU", "DEBUG")
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("IssuerContainer")))
                .withNetwork(network)
                .withNetworkAliases("swiyu_issuer")
                .withExtraHost("host.docker.internal", "host-gateway")
                .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("issuer/config/default/metadata.json")), "/tmp/metadata.json")
                .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("truststore.jks")), "/app/certs/truststore.jks")
                .withEnv("JAVA_TOOL_OPTIONS", "-Djavax.net.ssl.trustStore=/app/certs/truststore.jks -Djavax.net.ssl.trustStorePassword=changeit");

        issuer.waitingFor(Wait.forLogMessage(".*Started Application.*", 1));

        issuer.start();

        return issuer;
    }
}
