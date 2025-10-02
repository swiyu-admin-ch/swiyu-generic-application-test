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

public class VerifierContainer {

    public static GenericContainer<?> startVerifierContainer(Network network, PostgreSQLContainer<? extends PostgreSQLContainer<?>> dbContainer, GenericContainer<?> mockServer) {

        var imageName = "ghcr.io/swiyu-admin-ch/swiyu-verifier:main";

        var mockServerUri = toUri("https://%s:%s".formatted("mockserver", 1080)).toString();

        var jdbcUrl = String.format("jdbc:postgresql://%s:5432/%s?currentSchema=%s", DB_ALIAS, dbContainer.getDatabaseName(), "swiyu_verifier");

        var did = "did:example:12345";

        var verifier = new GenericContainer<>(imageName)
                .withExposedPorts(8080)
                .withEnv("VERIFIER_DID", did)
                .withEnv("OPENID_CLIENT_METADATA_FILE", "file:///tmp/metadata.json")
                .withEnv("EXTERNAL_URL", "http://default-verifier-url.admin.ch")
                .withEnv("DID_STATUS_LIST_VERIFICATION_METHOD", did + "#assert-key-01")
                .withEnv("STATUS_LIST_CACHE_TTL_MILLI", "50")
                .withEnv("SIGNING_KEY", "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIDqMm9PvL4vpyFboAwaeViQsH30CkaDcVtRniZPezFxpoAoGCCqGSM49\nAwEHoUQDQgAEQgjeqGSdu+2jq8+n78+6fXk2Yh22lQKBYCnu5FWPvKtat3wFEsQX\nqNHYgPXBxWmOBw5l2PE/gUDUJqGJSc1LuQ==\n-----END EC PRIVATE KEY-----")
                .withEnv("APPLICATION_ACCEPTED_STATUS_LIST_HOSTS_0", "mockserver")
                .withEnv("ACCEPTED_STATUS_LIST_HOSTS", mockServerUri)
                .withEnv("client_id_scheme", "did")
                .withEnv("LOGGING_LEVEL_ORG_SPRINGFRAMEWORK_WEB_SERVLET_MVC_SUPPORT", "DEBUG")
                .withEnv("ACCEPTED_STATUS_LIST_HOSTS", "swiyu-demo-verifier-service")
                .withEnv("MANAGEMENT_HEALTH_KUBERNETES_ENABLED", "false")
                .withEnv("MANAGEMENT_INFO_KUBERNETES_ENABLED", "false")
                .withEnv("POSTGRES_JDBC", jdbcUrl)
                .withEnv("POSTGRES_USER", dbContainer.getUsername())
                .withEnv("POSTGRES_PASSWORD", dbContainer.getPassword())
                .withEnv("SPRING_DATASOURCE_URL", jdbcUrl)
                .withEnv("SPRING_DATASOURCE_USERNAME", dbContainer.getUsername())
                .withEnv("SPRING_DATASOURCE_PASSWORD", dbContainer.getPassword())
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("VerifierContainer")))
                .withNetwork(network)
                .withNetworkAliases("swiyu_verifier")
                .withExtraHost("host.docker.internal", "host-gateway")
                .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("verifier/config/default/metadata.json")), "/tmp/metadata.json")
               // .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("cacerts")), "/opt/java/openjdk/lib/security/cacerts")
                .waitingFor(Wait.forLogMessage(".*Started Application.*", 1))
                .withCopyFileToContainer(MountableFile.forHostPath(getResourcePath("truststore.jks")), "/app/certs/truststore.jks")
                .withEnv("JAVA_TOOL_OPTIONS", "-Djavax.net.ssl.trustStore=/app/certs/truststore.jks -Djavax.net.ssl.trustStorePassword=changeit");

        verifier.start();

        return verifier;
    }
}
