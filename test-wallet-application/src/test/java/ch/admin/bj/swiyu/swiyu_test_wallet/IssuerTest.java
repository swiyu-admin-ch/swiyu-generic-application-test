package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.gen.issuer.model.OpenIdConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuanceService;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerMetadata;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.JsonConverter.toJsonNode;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(IssuerTestContainerTestConfiguration.class)
class IssuerTest {

    @Autowired
    IssuerImageConfig issuerImageConfig;
    @Autowired
    VerifierImageConfig verifierImageConfig;
    @Autowired
    IssuerConfig issuerConfig;
    @Autowired
    MockServerContainer mockServer;
    @Autowired(required = false)
    GenericContainer<?> issuerContainer;
    @Autowired
    PostgreSQLContainer<?> dbTestContainer;

    @Value("${ISSUER_HOST:localhost}")
    String issuerHostEnv;
    @Value("${ISSUER_PORT:8081}")
    int issuerPortEnv;

    private BusinessIssuer issuerManager;
    private IssuanceService issuanceService;

    @BeforeEach
    void setup() {
        String issuerHost;
        int issuerPort;
        if (issuerContainer != null) {
            issuerHost = issuerContainer.getHost();
            issuerPort = issuerContainer.getMappedPort(8080);
        } else {
            issuerHost = issuerHostEnv;
            issuerPort = issuerPortEnv;
        }
        issuerConfig.setIssuerServiceUrl(toUri("http://%s:%s".formatted(issuerHost, issuerPort)).toString());
        issuerManager = new BusinessIssuer(issuerConfig);
        issuanceService = new IssuanceService(toUri("http://%s:%s".formatted(issuerHost, issuerPort)).toString());
        issuerManager.createStatusList(100000, 2);
    }

    @Test
    @Tag("issuer")
    @Tag("infrastructure")
    void issuerManagementShouldBeHealthy() {

        var health = issuerManager.health();

        assertThat(health)
                .isNotNull()
                .containsEntry("status", "UP");
    }

    @Test
    @Tag("issuer")
    void offerDeepLinkWithSDJwt() {

        var credentialDetails = issuerManager.createCredentialOffer("university_example_sd_jwt");
        var deeplink = toUri(credentialDetails.getOfferDeeplink());

        assertThat(deeplink.getScheme()).isEqualTo("swiyu");
        assertThat(deeplink.getQuery()).isNotNull();
        var credentialOfferQueryParam = PathSupport.splitQuery(deeplink).get("credential_offer");
        assertThat(credentialOfferQueryParam).isNotNull();

        var credentialOffer = toJsonNode(credentialOfferQueryParam);
        assertThat(credentialOffer.get("credential_issuer")).isNotNull();
        assertThat(credentialOffer.get("grants")).isNotNull();
        assertThat(credentialOffer.get("grants").get("urn:ietf:params:oauth:grant-type:pre-authorized_code")).isNotNull();
        assertThat(credentialOffer.get("grants").get("urn:ietf:params:oauth:grant-type:pre-authorized_code").get("pre-authorized_code")).isNotNull();
        var code = credentialOffer.at("/grants/urn:ietf:params:oauth:grant-type:pre-authorized_code/pre-authorized_code").asText();
        assert credentialDetails.getManagementId() != null;
        assertThat(code)
                .isNotNull()
                .isNotEmpty()
                .isNotEqualTo(credentialDetails.getManagementId().toString());
    }

    // @TestIssuerContext
    @Tag("issuer")
    void validateMetadata() {
        IssuerMetadata metadata = issuanceService.getWellKnownCredentialIssuerInfo();

        assertThat(metadata.getIssuerURI()).startsWith("http://default-issuer-url.admin.ch");
        assertThat(metadata.getDisplay()).isNotNull();
        assertThat(metadata.getSupportedCredentialConfigurations()).isNotNull();
        assertThat(metadata.getSupportedCredentialConfigurations().get("university_example_sd_jwt")).isNotNull();
    }

    @Test
    @Tag("issuer")
    void validateConfiguration() {
        var openIdConfig = issuanceService.getWellKnownOpenIdConfiguration();

        assertThat(openIdConfig.getIssuer()).isNotNull();
        assertThat(openIdConfig.getIssuer()).startsWith("http://default-issuer-url.admin.ch");
        assertThat(openIdConfig.getTokenEndpoint()).isNotNull();
        assertThat(openIdConfig.getTokenEndpoint()).isEqualTo("http://default-issuer-url.admin.ch/oid4vci/api/token");
    }

    @Test
    @Tag("issuer")
    void validateOAuthAuthorizationServer() {
        OpenIdConfiguration openIdConfig = issuanceService.getWellKnownOAuthAuthorizationServer();

        assertThat(openIdConfig.getIssuer()).isNotNull();
        assertThat(openIdConfig.getIssuer()).startsWith("http://default-issuer-url.admin.ch");
        assertThat(openIdConfig.getTokenEndpoint()).isNotNull();
        assertThat(openIdConfig.getTokenEndpoint()).isEqualTo("http://default-issuer-url.admin.ch/oid4vci/api/token");
    }
}
