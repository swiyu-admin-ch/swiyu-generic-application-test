package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.StatusResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Map;
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
                    This test validates that the Business Issuer can successfully retrieve the current status of a
                    non-deferred credential offer immediately after creation through the issuer management API.
                    """
    )
    @Tag(ReportingTags.UCI_C2)
    @Tag(ReportingTags.HAPPY_PATH)
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
                    This test validates that the Business Issuer can successfully retrieve the current status of a
                    deferred credential offer through the issuer management API.
                    """
    )
    @Tag(ReportingTags.UCI_C2)
    @Tag(ReportingTags.HAPPY_PATH)
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
                    This test validates that the Business Issuer receives HTTP 404 when attempting to retrieve
                    the status of a non-existent credential through the issuer management API.
                    """
    )
    @Tag(ReportingTags.UCI_C2)
    @Tag(ReportingTags.EDGE_CASE)
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
                    This test validates that the Business Issuer can successfully update a credential's status
                    through valid state transitions, confirming that status management operations follow defined
                    credential lifecycle rules.
                    """
    )
    @Tag(ReportingTags.UCI_C3)
    @Tag(ReportingTags.HAPPY_PATH)
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
                    This test validates that the Business Issuer receives HTTP 400 when attempting invalid
                    credential state transitions such as transitioning from CANCELLED back to ISSUED,
                    ensuring that revocation is permanent and lifecycle constraints are enforced.
                    """
    )
    @Tag(ReportingTags.UCI_C3)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC},
            reason = "This feature is not available yet"
    )
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

        Assertions.assertThat(errorCode(ex))
                .isEqualTo(400);
        final Map<String, String> error = errorJson(ex);
        Assertions.assertThat(error)
                .containsEntry("error_description", "Bad Request")
                .containsEntry("detail", "Issuance process may not be skipped");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-580",
            summary = "Business issuer successfully retrieves the status list resource",
            description = """
                    This test validates that the Business Issuer can successfully fetch the current status list resource
                    which contains the up-to-date status of all managed credentials, essential for credential management
                    and audit purposes.
                    """
    )
    @Tag(ReportingTags.UCI_S2)
    @Tag(ReportingTags.HAPPY_PATH)
    void retrieveStatusList_thenSuccess() {
        log.info("Retrieving status list resource...");
        final String statusListUrl = getCurrentStatusList().getStatusRegistryUrl();
        assertThat(statusListUrl).isNotBlank();

        log.info("Status list URL: {}", statusListUrl);
        log.info("Status list retrieved successfully");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-581",
            summary = "Business issuer cannot retrieve non-existent status list",
            description = """
                    This test validates that the Business Issuer receives HTTP 404 when attempting to retrieve
                    a non-existent status list, ensuring proper error handling for missing resources.
                    """
    )
    @Tag(ReportingTags.UCI_S2)
    @Tag(ReportingTags.EDGE_CASE)
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
