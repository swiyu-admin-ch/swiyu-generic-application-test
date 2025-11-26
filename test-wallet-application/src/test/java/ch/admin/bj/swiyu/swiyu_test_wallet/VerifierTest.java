package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.testcontainers.containers.GenericContainer;

import java.util.UUID;

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
            key = "EIDOMNI-463",
            summary = "Successful deeplink creation for verification request",
            description = """
                    This test validates the end-to-end flow for deeplink verification, 

                    Steps:
                    1. The verifier initiates a verification request following the OID4VP flow.
                    2. The wallet retrieves verification details 
                    """
    )
    @Tag("verification")
    void verifierProvidesDeeplink() {
        final ManagementResponse deeplink = verifierManager.verificationRequest().acceptedIssuerDid(UUID.randomUUID().toString()).createManagementResponse();
        assertThat(deeplink.getVerificationDeeplink())
                .isNotNull()
                .startsWith("swiyu-verify://");
    }
}
