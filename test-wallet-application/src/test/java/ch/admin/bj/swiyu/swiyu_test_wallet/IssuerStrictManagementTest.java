package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.StatusResponse;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.HttpClientErrorException;

import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@ActiveProfiles({"issuer-strict"})
class IssuerStrictManagementTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-582",
            summary = "Business issuer cannot access management endpoint without JWT when JWT protection is enabled",
            description = """
                    Validate that when JWT authentication is enabled on the management endpoint,
                    requests without a valid JWT are rejected with 401 Unauthorized.
                    This ensures the management API is properly protected.
                    """
    )
    @Tag("uci_p1")
    @Tag("edge_case")
    @Disabled
    void updateCredentialStatus_WithoutJwt_thenUnauthorized() {
        log.info("Creating credential...");
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final UUID managementId = response.getManagementId();

        log.info("Attempting to update status without JWT (should fail with 401)");
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> issuerManager.updateState(managementId,
                        ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType.CANCELLED)
        );

        assertThat(errorCode(ex))
                .as("Request without JWT should be rejected with 401 Unauthorized")
                .isEqualTo(401);

        log.info("Request correctly rejected: JWT authentication is enforced");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-583",
            summary = "Business issuer can access management endpoint with valid JWT",
            description = """
                    Validate that when a valid JWT is provided, the business issuer can successfully
                    access the management endpoint and perform credential status updates.
                    This test ensures that authorized requests with valid JWTs are accepted.
                    """
    )
    @Tag("uci_p1")
    @Tag("happy_path")
    @Disabled
    void updateCredentialStatus_WithValidJwt_thenSuccess() {
        log.info("Creating credential with JWT...");
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final UUID managementId = response.getManagementId();

        log.info("Updating status with valid JWT (should succeed)");
        issuerManager.updateState(managementId,
                ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType.CANCELLED);

        final StatusResponse status = issuerManager.getStatusById(managementId);
        assertThat(status.getStatus()).isEqualTo(ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType.CANCELLED);

        log.info("Status update successful with JWT authentication");
    }
}

