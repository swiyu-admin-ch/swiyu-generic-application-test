package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.HttpClientErrorException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@ActiveProfiles({"issuer-strict"})
class IssuerStrictManagementTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-582",
            summary = "Business issuer can create status list via POST endpoint with signed JWT body",
            description = """
                    Validate that when a signed JWT with valid credentials is provided in the body,
                    the business issuer can successfully create a status list via the
                    POST /management/api/status-list endpoint.
                    This test ensures that authorized POST requests with valid signed JWT bodies are accepted.
                    """
    )
    @Tag("uci_s1")
    @Tag("uci_p1")
    @Tag("happy_path")
    void createStatusList_WithSignedJwtBody_thenSuccess() {
        log.info("Creating status list with signed JWT body (should succeed)");
        final StatusList statusList = issuerManager.createStatusListWithSignedJwt(10000, 2, jwtKey, "test-key-1");

        assertThat(statusList)
                .as("Status list should be created successfully with valid signed JWT")
                .isNotNull();
        assertThat(statusList.getStatusRegistryUrl())
                .as("Status list should have a valid registry URL")
                .isNotNull();

        log.info("Status list created successfully with signed JWT authentication");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-583",
            summary = "Business issuer cannot create status list with unauthenticated JWT key",
            description = """
                    Validate that when an unauthenticated JWT key is used in the body,
                    the business issuer cannot create a status list and receives a 401 Unauthorized response.
                    This test ensures that the management endpoint properly validates JWT signatures.
                    """
    )
    @Tag("uci_s1")
    @Tag("uci_p1")
    @Tag("edge_case")
    void createStatusList_WithUnauthenticatedJwtBody_thenUnauthorized() {
        log.info("Attempting to create status list with unauthenticated JWT body (should fail with 401)");
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> issuerManager.createStatusListWithSignedJwt(10000, 2, unauthenticatedJwtKey, "test-key-1")
        );

        assertThat(errorCode(ex))
                .as("Request with unauthenticated JWT should be rejected with 401 Unauthorized")
                .isEqualTo(401);

        assertThat(errorJson(ex))
                .containsEntry("error", "Unauthorized")
                .containsEntry("path", "/management/api/status-list");

        log.info("Request correctly rejected: JWT signature validation is enforced");
    }
}

