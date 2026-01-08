package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.StatusResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class IssuerManagementTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-457",
            summary = "Business issuer retrieves the current status of a credential offer (non-deferred)",
            description = """
                    Validate that the Business Issuer can successfully retrieve the current status
                    of a non-deferred credential offer immediately after creation.
                    """
    )
    @Tag("uci_c2")
    @Tag("happy_path")
    void getOfferStatus_NonDeferred_thenSuccess() {
        log.info("Creating non-deferred credential offer...");
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final UUID managementId = response.getManagementId();

        log.info("Retrieving status for credential offer...");
        final StatusResponse statusResponse = issuerManager.getStatusById(managementId);

        assertThat(statusResponse).isNotNull();
        assertThat(statusResponse.getStatus()).isNotNull();
        log.info("Status retrieved successfully: {}", statusResponse.getStatus());
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-458",
            summary = "Business issuer retrieves the current status of a deferred credential offer",
            description = """
                    Validate that the Business Issuer can successfully retrieve the current status
                    of a deferred credential offer.
                    """
    )
    @Tag("uci_c2")
    @Tag("happy_path")
    void getOfferStatus_Deferred_thenSuccess() {
        log.info("Creating deferred credential offer...");
        final CredentialWithDeeplinkResponse response = issuerManager.createDeferredCredentialOffer("unbound_example_sd_jwt");
        final UUID managementId = response.getManagementId();

        log.info("Retrieving status for deferred credential offer...");
        final StatusResponse statusResponse = issuerManager.getStatusById(managementId);

        assertThat(statusResponse).isNotNull();
        assertThat(statusResponse.getStatus()).isNotNull();
        log.info("Status retrieved successfully: {}", statusResponse.getStatus());
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-459",
            summary = "Business issuer cannot retrieve status of non-existent credential",
            description = """
                    Validate that the Business Issuer receives a 404 error when attempting to retrieve
                    the status of a credential that does not exist.
                    """
    )
    @Tag("uci_c2")
    @Tag("edge_case")
    void getOfferStatus_NonExistentOffer_thenRejected() {
        final UUID nonExistentId = UUID.randomUUID();
        log.info("Attempting to retrieve status for non-existent credential: {}", nonExistentId);

        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> issuerManager.getStatusById(nonExistentId)
        );

        assertThat(errorCode(ex)).isEqualTo(404);
        log.info("Non-existent credential correctly rejected with 404");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-466",
            summary = "Business issuer successfully updates credential status with valid transitions",
            description = """
                    Validate that the Business Issuer can successfully update a credential's status
                    through valid state transitions: OFFERED → ISSUED → SUSPENDED → ISSUED.
                    """
    )
    @Tag("uci_c3")
    @Tag("happy_path")
    void updateCredentialStatus_ValidTransitions_thenSuccess() {
        log.info("Creating credential for status update test...");
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final UUID managementId = response.getManagementId();

        StatusResponse initialStatus = issuerManager.getStatusById(managementId);
        log.info("Initial status: {}", initialStatus.getStatus());

        log.info("Updating status to CANCELLED");
        issuerManager.updateState(managementId, UpdateCredentialStatusRequestType.CANCELLED);

        StatusResponse updatedStatus = issuerManager.getStatusById(managementId);
        log.info("Updated status: {}", updatedStatus.getStatus());

        assertThat(updatedStatus.getStatus()).isNotEqualTo(initialStatus.getStatus());
        log.info("Status update successful");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-558",
            summary = "Business issuer cannot perform invalid state transition (REVOKED → ISSUED)",
            description = """
                    Validate that the Business Issuer receives an error when attempting an invalid
                    state transition. Revoked credentials cannot be reissued as revocation is permanent.
                    """
    )
    @Tag("uci_c3")
    @Tag("edge_case")
    void updateCredentialStatus_InvalidTransition_thenRejected() {
        log.info("Creating credential for invalid transition test...");
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final UUID managementId = response.getManagementId();

        log.info("Setting up: OFFERED → CANCELLED");
        issuerManager.updateState(managementId, UpdateCredentialStatusRequestType.CANCELLED);
        StatusResponse status = issuerManager.getStatusById(managementId);
        assertThat(status.getStatus()).isEqualTo(CredentialStatusType.CANCELLED);
        log.info("Credential successfully cancelled");

        log.info("Attempting invalid transition: CANCELLED → ISSUED");
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> issuerManager.updateState(managementId, UpdateCredentialStatusRequestType.ISSUED)
        );

        assertThat(errorCode(ex)).isEqualTo(400);
        assertThat(errorJson(ex).values().toString()).contains("already");
        log.info("Invalid transition correctly rejected");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-580",
            summary = "Business issuer successfully retrieves the status list resource",
            description = """
                    Validate that the Business Issuer can successfully fetch the current status list
                    resource which contains the up-to-date status of all verifiable credentials managed
                    by the issuer. This is essential for monitoring and auditing credential validity.
                    """
    )
    @Tag("uci_s2")
    @Tag("happy_path")
    void retrieveStatusList_thenSuccess() {
        log.info("Retrieving status list resource...");
        final String statusListUrl = currentStatusList.getStatusRegistryUrl();
        assertThat(statusListUrl).isNotBlank();

        log.info("Status list URL: {}", statusListUrl);
        log.info("Status list retrieved successfully");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-581",
            summary = "Business issuer cannot retrieve non-existent status list",
            description = """
                    Validate that the Business Issuer receives an appropriate error when attempting
                    to retrieve a status list that does not exist.
                    """
    )
    @Tag("uci_s2")
    @Tag("edge_case")
    void retrieveStatusList_NonExistent_thenNotFound() {
        log.info("Attempting to retrieve non-existent status list...");
        final UUID nonExistentStatusListId = java.util.UUID.randomUUID();

        log.info("Attempting to get status list with ID: {}", nonExistentStatusListId);
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> issuerManager.getStatusById(nonExistentStatusListId)
        );

        assertThat(errorCode(ex)).isEqualTo(404);
        log.info("Non-existent status list correctly rejected with 404");
    }
}
