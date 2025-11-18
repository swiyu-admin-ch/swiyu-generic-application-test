package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierTest {
    @Autowired
    VerifierImageConfig verifierImageConfig;
    @Autowired
    GenericContainer<?> verifierContainer;
    private VerifierManager verifierManager;

    @BeforeAll
    void setup() throws Exception {
        verifierManager = new VerifierManager(toUri("http://%s:%s".formatted(verifierContainer.getHost(), verifierContainer.getMappedPort(8080))).toString());
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
    void verifierManagementShouldBeHealthy() {
        final Map<String, Object> health = verifierManager.health();
        assertThat(health)
                .isNotNull()
                .containsEntry("status", "UP");
    }

    @Test
    void verifierProvidesDeeplink() {
        final ManagementResponse deeplink = verifierManager.createVerificationRequest(VerificationRequests.createDefaultRequest(false, false));
        assertThat(deeplink.getVerificationDeeplink())
                .isNotNull()
                .startsWith("swiyu-verify://");
    }
}
