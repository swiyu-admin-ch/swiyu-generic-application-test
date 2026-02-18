package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialInfoResponse;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.HttpClientErrorException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@ActiveProfiles({"issuer-strict"})
class IssuerStrictManagementTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-582",
            summary = "Access to Issuer Management operations using a valid signed JWT",
            description = """
                    This test validates that access to Issuer Management operations is correctly controlled using signed JWT
                    authentication. A Business Issuer with valid JWT credentials can successfully perform authorized management
                    actions including status list creation and credential issuance.
                    """
    )
    @Tag(ReportingTags.UCI_S1)
    @Tag(ReportingTags.UCI_P1)
    @Tag(ReportingTags.HAPPY_PATH)
    void issuerManagementAccess_withSignedJwt_thenSuccess() {
        log.info("Creating status list with signed JWT body (should succeed)");
        final StatusList statusList = issuerManager.createStatusListWithSignedJwt(jwtKey, "test-key-1", 10000, 2);

        assertThat(statusList)
                .as("Status list should be created successfully with valid signed JWT")
                .isNotNull();
        assertThat(statusList.getStatusRegistryUrl())
                .as("Status list should have a valid registry URL")
                .isNotNull();

        final CredentialWithDeeplinkResponse credentialInfo = issuerManager.createCredentialWithSignedJwt(jwtKey, "test-key-1", "bound_example_sd_jwt");

        assertThat(credentialInfo).isNotNull();

        final CredentialInfoResponse credentialManagement = issuerManager.getCredentialById(credentialInfo.getManagementId());

        assertThat(credentialManagement).isNotNull();
        assertThat(credentialManagement.getStatus()).isEqualTo(CredentialStatusType.OFFERED);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-583",
            summary = "Access to Issuer Management operations using an unauthorized signed JWT is denied",
            description = """
                    This test validates that access to Issuer Management operations is correctly denied when an unauthorized signed JWT is provided.
                    It ensures that authentication and access control rules are enforced, preventing a Business Issuer from performing management
                    actions when the JWT is not trusted.
                    """
    )
    @Tag(ReportingTags.UCI_S1)
    @Tag(ReportingTags.UCI_P1)
    @Tag(ReportingTags.EDGE_CASE)
    void issuerManagementAccess_withUnauthorizedSignedJwt_thenRejected() {
        HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> issuerManager.createStatusList(10000, 2)
        );

        assertThat(errorCode(ex))
                .as("Request with unauthenticated JWT should be rejected with 401 Unauthorized")
                .isEqualTo(401);

        assertThat(errorJson(ex))
                .containsEntry("error", "Unauthorized")
                .containsEntry("path", "/management/api/status-list");

        ex = assertThrows(
                HttpClientErrorException.class,
                () -> issuerManager.createCredentialWithSignedJwt(unauthenticatedJwtKey, "test-key-1", "bound_example_sd_jwt")
        );

        assertThat(errorCode(ex))
                .as("Request with unauthenticated JWT should be rejected with 401 Unauthorized")
                .isEqualTo(401);

        assertThat(errorJson(ex))
                .containsEntry("error", "Unauthorized")
                .containsEntry("path", "/management/api/credentials");
    }
}

