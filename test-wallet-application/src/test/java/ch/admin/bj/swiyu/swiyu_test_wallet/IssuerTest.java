package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.OpenIdConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuanceService;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerMetadata;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.JsonConverter.toJsonNode;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class IssuerTest {

    @Autowired
    IssuerImageConfig issuerImageConfig;
    @Autowired
    IssuerConfig issuerConfig;
    @Autowired
    MockServerContainer mockServer;
    @Autowired
    GenericContainer<?> issuerContainer;
    @Autowired
    PostgreSQLContainer<?> dbTestContainer;

    private BusinessIssuer issuerManager;
    private IssuanceService issuanceService;

    @BeforeAll
    void setup() {
        issuerConfig.setIssuerServiceUrl(toUri("http://%s:%s".formatted(issuerContainer.getHost(), issuerContainer.getMappedPort(8080))).toString());
        issuerManager = new BusinessIssuer(issuerConfig);
        issuanceService = new IssuanceService(toUri("http://%s:%s".formatted(issuerContainer.getHost(), issuerContainer.getMappedPort(8080))).toString());
        issuerManager.createStatusList(100000, 2);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-394",
            summary = "Issuer management service health check",
            description = """
                    This test validates that the issuer management service is operational and responding as expected. 
                    It ensures that the infrastructure components required for OID4VCI issuance are properly initialized 
                    and report a healthy system state.
                    
                    Steps:
                    1. The issuer management service health endpoint is called.
                    2. The health response is parsed and evaluated.
                    3. The test asserts that the health status equals UP, confirming successful initialization.
                    """
    )
    @Tag("infrastructure")
    void issuerManagementShouldBeHealthy() {
        final Map<String, Object> health = issuerManager.health();
        assertThat(health)
                .isNotNull()
                .containsEntry("status", "UP");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-387",
            summary = "Credential offer deeplink creation with SD-JWT content",
            description = """
                    This test validates that the issuer correctly generates a credential offer deeplink for an SD-JWT credential 
                    according to the OID4VCI specification. It ensures that the deeplink contains all required parameters and that 
                    the pre-authorized code differs from the management ID for security reasons.
                    
                    Steps:
                    1. The issuer creates a credential offer for an SD-JWT credential (e.g., university_example_sd_jwt).
                    2. The deeplink URI is parsed and its scheme validated as 'swiyu'.
                    3. The query parameters of the deeplink are decoded and validated.
                    4. The credential offer object is inspected for required fields: credential_issuer and grants.
                    5. The test asserts that the pre-authorized code is present and unique from the management ID.
                    """
    )
    @Tag("issuance")
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

    @Test
    @XrayTest(
            key = "EIDOMNI-415",
            summary = "Issuer metadata endpoint validation",
            description = """
                    This test ensures that the issuer's metadata endpoint correctly exposes OID4VCI-compliant configuration data. 
                    It validates that the issuer URI, display information, and supported credential configurations are available 
                    and properly structured.
                    
                    Steps:
                    1. The issuer metadata endpoint (.well-known/openid-credential-issuer) is retrieved.
                    2. The issuer URI is validated to start with the expected base URL.
                    3. The display metadata and credential configurations are checked for presence.
                    4. The SD-JWT credential configuration 'university_example_sd_jwt' is verified to be included.
                    """
    )
    @Tag("issuance")
    void validateMetadata() {
        IssuerMetadata metadata = issuanceService.getWellKnownCredentialIssuerInfo();

        assertThat(metadata.getIssuerURI()).startsWith("http://default-issuer-url.admin.ch");
        assertThat(metadata.getDisplay()).isNotNull();
        assertThat(metadata.getSupportedCredentialConfigurations()).isNotNull();
        assertThat(metadata.getSupportedCredentialConfigurations().get("university_example_sd_jwt")).isNotNull();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-391",
            summary = "OpenID configuration validation for OID4VCI issuer",
            description = """
                    This test validates that the issuer’s OpenID configuration endpoint (.well-known/openid-configuration) 
                    is correctly implemented for OID4VCI flows. It confirms that the issuer and token endpoint URLs 
                    match the expected configuration pattern.
                    
                    Steps:
                    1. The OpenID configuration endpoint is fetched from the issuer.
                    2. The issuer URL is validated to match the default base URL.
                    3. The token endpoint is verified to be correctly defined and reachable.
                    4. The test asserts compliance with expected OID4VCI configuration.
                    """
    )
    @Tag("issuance")
    void validateConfiguration() {
        var openIdConfig = issuanceService.getWellKnownOpenIdConfiguration();

        assertThat(openIdConfig.getIssuer()).isNotNull();
        assertThat(openIdConfig.getIssuer()).startsWith("http://default-issuer-url.admin.ch");
        assertThat(openIdConfig.getTokenEndpoint()).isNotNull();
        assertThat(openIdConfig.getTokenEndpoint()).isEqualTo("http://default-issuer-url.admin.ch/oid4vci/api/token");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-385",
            summary = "OAuth authorization server configuration validation for OID4VCI",
            description = """
                    This test validates that the OAuth authorization server endpoint exposed by the issuer 
                    is correctly aligned with OID4VCI requirements. It ensures that authorization metadata 
                    and token endpoint URLs are configured consistently with the OpenID provider configuration.
                    
                    Steps:
                    1. The issuer's OAuth authorization server configuration is retrieved.
                    2. The issuer URL is validated to match the expected base address.
                    3. The token endpoint is checked for existence and correctness.
                    4. The test confirms that the configuration aligns with OID4VCI authorization flow expectations.
                    """
    )
    @Tag("issuance")
    void validateOAuthAuthorizationServer() {
        OpenIdConfiguration openIdConfig = issuanceService.getWellKnownOAuthAuthorizationServer();

        assertThat(openIdConfig.getIssuer()).isNotNull();
        assertThat(openIdConfig.getIssuer()).startsWith("http://default-issuer-url.admin.ch");
        assertThat(openIdConfig.getTokenEndpoint()).isNotNull();
        assertThat(openIdConfig.getTokenEndpoint()).isEqualTo("http://default-issuer-url.admin.ch/oid4vci/api/token");
    }
}
