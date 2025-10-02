package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.gen.issuer.model.CredentialOfferRequest;
import ch.admin.bj.swiyu.gen.issuer.model.OpenIdConfiguration;
import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.CredentialOffer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuanceService;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerMetadata;
import ch.admin.bj.swiyu.swiyu_test_wallet.testcontainer.DBContainer;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;

import static ch.admin.bj.swiyu.swiyu_test_wallet.testcontainer.IssuerContainer.getIssuerContainer;
import static ch.admin.bj.swiyu.swiyu_test_wallet.testcontainer.MockServerContainer.getMockServer;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.JsonConverter.toJsonNode;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.DEFINED_PORT;

@Testcontainers
@SpringBootTest(webEnvironment = DEFINED_PORT)
class IssuerTest extends BaseTest {

    private final Network network = Network.newNetwork();

    @Container
    PostgreSQLContainer<?> dbContainer = DBContainer.startupDbContainer(network);

    @Container
    GenericContainer<?> mockServer = getMockServer(network);

    @Container
    GenericContainer<?> issuerContainer = getIssuerContainer(network, dbContainer);

    private BusinessIssuer issuerManager;
    private IssuanceService issuanceService;
    private StatusList statusList;

    @BeforeEach
    void setup() {
        IssuerConfig issuerConfig = new IssuerConfig();
        issuerConfig.setIssuerServiceUrl(toUri("http://%s:%s".formatted(issuerContainer.getHost(), issuerContainer.getMappedPort(8080))).toString());
        issuerManager = new BusinessIssuer(issuerConfig);
        issuanceService = new IssuanceService( toUri("http://%s:%s".formatted(issuerContainer.getHost(), issuerContainer.getMappedPort(8080))).toString());
        statusList = issuerManager.createStatusList(100000, 2);
    }

    @Test
    @Tag("issuer")
    @Tag("infrastructure")
    void issuerManagementShouldBeHealthy() {

        assertThat(dbContainer.isRunning()).isTrue();

        assertThat(issuerContainer.isRunning()).isTrue();

        var health = issuerManager.health();

        assertThat(health)
                .isNotNull()
                .containsEntry("status", "UP");
    }

    @Test
    @Tag("issuer")
    void offerDeepLinkWithSDJwt() {
        Assertions.assertNotNull(statusList);
        Assertions.assertNotNull(statusList.getStatusRegistryUrl());

        CredentialOfferRequest offer = new CredentialOfferRequest();
        offer.setCredentialSubjectData(CredentialOffer.defaultSubjectData());
        offer.setStatusLists(List.of(statusList.getStatusRegistryUrl()));
        offer.setCredentialMetadata(
                CredentialOffer.defaultMetadata()
        );
        offer.setMetadataCredentialSupportedId(List.of("university_example_sd_jwt"));
        offer.setOfferValiditySeconds(86400); // 24h

        var credentialDetails = issuerManager.createCredential(offer);
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
        assertThat(code)
                .isNotNull()
                .isNotEmpty()
                .isNotEqualTo(credentialDetails.getManagementId().toString());
    }

    @Test
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
