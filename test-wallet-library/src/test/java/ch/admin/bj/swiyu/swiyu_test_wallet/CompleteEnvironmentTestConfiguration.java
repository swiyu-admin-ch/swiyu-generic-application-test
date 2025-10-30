package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil;
import org.mockserver.client.MockServerClient;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;

import java.security.KeyPair;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.DBContainerConfig.createPostgreSQLContainer;
import static ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig.createMockServerClient;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.DidLogUtil.createDidLog;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.DidLogUtil.getDidFromDidLog;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil.createJWKFromKeyPair;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil.generateEC256KeyPair;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

@TestConfiguration(proxyBeanMethods = false)
public class CompleteEnvironmentTestConfiguration {

    @Bean
    public IssuerConfig issuerConfig() {
        KeyPair assertKeys = generateEC256KeyPair();
        KeyPair authKeys = generateEC256KeyPair();

        var assertJwk = createJWKFromKeyPair(assertKeys);
        var authJwk = createJWKFromKeyPair(authKeys);

        var id = UUID.randomUUID();
        var mockServerUri = "https://mockserver:1080";

        var identifierRegistryUrl = "%s/api/v1/did/%s".formatted(mockServerUri, id);
        var didLog = createDidLog(authJwk, assertJwk, toUri(identifierRegistryUrl));
        var issuerDid = getDidFromDidLog(didLog);

        return IssuerConfig.builder()
                .mockServerUri(mockServerUri)
                .issuerServiceUrl(null)
                .swiyuPartnerId(UUID.randomUUID().toString())
                .issuerRegistryEntry(identifierRegistryUrl)
                .issuerDid(issuerDid)
                .issuerDidLog(didLog)
                .issuerAssertKeyId(issuerDid + "#assert-key-01")
                .issuerAuthKeyId(issuerDid + "#auth-key-01")
                .issuerAssertKeyPemString(KeyUtil.getPrivateKeyPem(assertKeys))
                .issuerAuthKeyPemString(KeyUtil.getPrivateKeyPem(authKeys))
                .build();
    }


    @Bean
    public Network network() {
        return Network.newNetwork();
    }

    @Bean
    public PostgreSQLContainer<?> dbTestContainer(Network network) {

        var container = createPostgreSQLContainer(network);

        container.start();

        return container;
    }

    @Bean
    public GenericContainer<?> issuerContainer(Network network,
                                               PostgreSQLContainer<?> dbContainer,
                                               IssuerConfig config,
                                               MockServerContainer mockServer,
                                               IssuerImageConfig issuerImageConfig) {

        var imageName = issuerImageConfig.getBaseImage() + ":" + issuerImageConfig.getImageTag();

        var container = IssuerContainerConfig.createIssuerContainer(network, dbContainer, config, mockServer, imageName);

        container.start();

        return container;
    }

    @Bean
    public MockServerContainer mockServer(Network network) {

        return MockServerContainerConfig.createAndStartMockServerContainer(network, 1080);
    }

    @Bean
    public MockServerClient mockServerClient(MockServerContainer mockServer, IssuerConfig issuerConfig) {

        return createMockServerClient(mockServer, issuerConfig);
    }


    @Bean
    public GenericContainer<?> verifierContainer(Network network,
                                                 PostgreSQLContainer<? extends PostgreSQLContainer<?>> dbContainer,
                                                 IssuerConfig config,
                                                 VerifierImageConfig verifierImageConfig,
                                                 MockServerClient mockServerClient) {

        var imageName = verifierImageConfig.getBaseImage() + ":" + verifierImageConfig.getImageTag();

        var container = VerifierContainerConfig.createVerifierContainer(network, dbContainer, config, imageName);

        container.start();

        return container;
    }
}