package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.FileSupport;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.DBContainerConfig.createPostgreSQLContainer;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

@TestConfiguration(proxyBeanMethods = false)
@EnableConfigurationProperties({ IssuerImageConfig.class, VerifierImageConfig.class })
public class CompleteEnvironmentTestConfiguration {

    @Bean
    public String tokenDirPath() {
        try {
            String path = System.getProperty("user.dir") + "/target/softhsm-tokens";

            Path tokenPath = Paths.get(path);

            FileSupport.deleteDirectory(tokenPath);
            Files.createDirectories(tokenPath);

            try {
                Files.setPosixFilePermissions(
                        tokenPath,
                        PosixFilePermissions.fromString("rwxrwxrwx")
                );
            } catch (UnsupportedOperationException e) {
                java.io.File file = tokenPath.toFile();
                file.setReadable(true, false);
                file.setWritable(true, false);
                file.setExecutable(true, false);
            }

            return path;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create token directory", e);
        }
    }

    @Bean
    public HSMConfig hsmConfig() {
        return new HSMConfig();
    }

    @Bean
    public IssuerConfig issuerConfig(IssuerImageConfig issuerImageConfig, String tokenDirPath) {
        UUID id = UUID.randomUUID();
        return EnvironmentConfig.createIssuerConfig(
                toUri(String.format("https://%s/api/v1/did/%s", MockServerClientConfig.MOCKSERVER_HOST, id)),
                issuerImageConfig.isEnableHsm(),
                issuerImageConfig.isEnableHsm() ? tokenDirPath : null
        );
    }

    @Bean
    public Network network() {
        return Network.newNetwork();
    }

    @Bean
    public TrustConfig trustConfig() {
        UUID id = UUID.randomUUID();
        return EnvironmentConfig.createTrustConfig(toUri(String.format("https://%s/api/v1/did/%s", MockServerClientConfig.MOCKSERVER_HOST, id)));
    }

    @Bean
    public PostgreSQLContainer<?> dbTestContainer(Network network) {

        var container = createPostgreSQLContainer(network);

        container.start();

        return container;
    }

    @Bean
    public GenericContainer<?> softHsmContainer(Network network, String tokenDirPath, HSMConfig hsmConfig) {

        var container = HSMContainerConfig.createSoftHsmContainer(network, hsmConfig, tokenDirPath);

        container.start();

        return container;
    }

    @Bean
    public GenericContainer<?> issuerContainer(Network network,
                                               PostgreSQLContainer<?> dbContainer,
                                               IssuerConfig config,
                                               MockServerContainer mockServer,
                                               IssuerImageConfig issuerImageConfig,
                                               GenericContainer<?> softHsmContainer,
                                               String tokenDirPath) {

        var imageName = issuerImageConfig.getBaseImage() + ":" + issuerImageConfig.getImageTag();

        var container = IssuerContainerConfig.createIssuerContainer(network, dbContainer, config, mockServer, imageName, issuerImageConfig, tokenDirPath);

        container.dependsOn(softHsmContainer);
        container.start();

        return container;
    }

    @Bean
    public MockServerClientConfig mockServerClientConfig() {
        return new MockServerClientConfig();
    }

    @Bean
    public MockServerContainer mockServer(Network network, IssuerConfig issuerConfig, TrustConfig trustConfig, MockServerClientConfig mockServerClientConfig) {

        var container = MockServerContainerConfig.createMockServerContainer(network);

        container.start();

        mockServerClientConfig.createMockServerClient(container, issuerConfig, trustConfig);

        return container;
    }


    @Bean
    public GenericContainer<?> verifierContainer(Network network,
                                                 PostgreSQLContainer<? extends PostgreSQLContainer<?>> dbContainer,
                                                 IssuerConfig config,
                                                 VerifierImageConfig verifierImageConfig) {

        var imageName = verifierImageConfig.getBaseImage() + ":" + verifierImageConfig.getImageTag();

        var container = VerifierContainerConfig.createVerifierContainer(network, dbContainer, config, imageName, verifierImageConfig);

        container.start();

        return container;
    }
}