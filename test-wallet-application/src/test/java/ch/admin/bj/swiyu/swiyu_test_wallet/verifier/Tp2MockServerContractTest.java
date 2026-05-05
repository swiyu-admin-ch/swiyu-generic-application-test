package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.RestClient;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class Tp2MockServerContractTest extends BaseTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().findAndRegisterModules();

    @Test
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "TP2 mock trust-registry endpoints expose the expected statement structures",
            description = """
                    This test validates that the TP2 MockServer endpoints used by the verifier and issuer
                    return the expected paged response wrapper and signed TP2 statement payloads with the
                    required application-test fields.
                    """
    )
    @Tag(ReportingTags.HAPPY_PATH)
    void tp2MockRoutes_whenRequested_thenExposeExpectedListAndStatementStructures() throws Exception {
        RestClient client = RestClient.builder()
                .baseUrl("http://%s:%d".formatted(
                        mockServerContainer.getHost(),
                        mockServerContainer.getMappedPort(1080)
                ))
                .build();

        // Given / When
        String identityListBody = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v2/identity-trust-statement")
                        .queryParam("sub", issuerConfig.getIssuerDid())
                        .queryParam("page", 1)
                        .queryParam("size", 5)
                        .build())
                .retrieve()
                .body(String.class);

        String verificationStatementJti = "07f289d5-8b1f-4604-bf72-53bdcb71ee05";
        String verificationStatementBody = client.get()
                .uri("/api/v2/verification-query-public-statement/{jti}", verificationStatementJti)
                .retrieve()
                .body(String.class);

        String issuanceAuthorizationBody = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v2/protected-issuance-authorization-trust-statement")
                        .queryParam("sub", issuerConfig.getIssuerDid())
                        .queryParam("page", 0)
                        .queryParam("size", 1)
                        .build())
                .retrieve()
                .body(String.class);

        // Then
        assertIdentityTrustStatementList(identityListBody);
        assertVerificationQueryPublicStatement(verificationStatementBody, verificationStatementJti);
        assertProtectedIssuanceAuthorizationList(issuanceAuthorizationBody);
    }

    private void assertIdentityTrustStatementList(String responseBody) throws Exception {
        Map<String, Object> response = OBJECT_MAPPER.readValue(responseBody, new TypeReference<>() {
        });
        @SuppressWarnings("unchecked")
        List<String> content = (List<String>) response.get("content");
        @SuppressWarnings("unchecked")
        Map<String, Object> page = (Map<String, Object>) response.get("page");

        assertThat(content).hasSize(1);
        assertThat(page)
                .containsEntry("size", 5)
                .containsEntry("number", 1)
                .containsEntry("totalPages", 1)
                .containsEntry("totalElements", 1);

        SignedJWT statement = SignedJWT.parse(content.getFirst());
        assertThat(statement.getHeader().getType().toString()).isEqualTo("swiyu-identity-trust-statement+jwt");
        assertThat(statement.getHeader().getCustomParam("profile_version")).isEqualTo("swiss-profile-trust:2.0.0");
        assertThat(statement.getJWTClaimsSet().getSubject()).isEqualTo(issuerConfig.getIssuerDid());
        assertThat(statement.getJWTClaimsSet().getStringClaim("entity_name")).isEqualTo("Mock TP2 Issuer");
        assertThat(statement.getJWTClaimsSet().getJSONObjectClaim("status")).containsKey("status_list");
        assertThat(statement.getJWTClaimsSet().getClaim("registry_ids")).isInstanceOf(List.class);
    }

    private void assertVerificationQueryPublicStatement(String jwt, String expectedJti) throws ParseException {
        SignedJWT statement = SignedJWT.parse(jwt);

        assertThat(statement.getHeader().getType().toString())
                .isEqualTo("swiyu-verification-query-public-statement+jwt");
        assertThat(statement.getJWTClaimsSet().getJWTID()).isEqualTo(expectedJti);
        assertThat(statement.getJWTClaimsSet().getStringClaim("purpose_name")).isEqualTo("Employment check");

        @SuppressWarnings("unchecked")
        Map<String, Object> request = (Map<String, Object>) statement.getJWTClaimsSet().getClaim("request");
        @SuppressWarnings("unchecked")
        Map<String, Object> query = (Map<String, Object>) request.get("query");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) query.get("credentials");
        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) credentials.getFirst().get("meta");

        assertThat(request).containsEntry("type", "DCQL");
        assertThat(request).containsEntry("scope", "ch.swiyu.tp2.employment.presentation");
        assertThat(meta.get("vct_values")).isEqualTo(List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT));
    }

    private void assertProtectedIssuanceAuthorizationList(String responseBody) throws Exception {
        Map<String, Object> response = OBJECT_MAPPER.readValue(responseBody, new TypeReference<>() {
        });
        @SuppressWarnings("unchecked")
        List<String> content = (List<String>) response.get("content");

        assertThat(content).hasSize(1);

        SignedJWT statement = SignedJWT.parse(content.getFirst());
        assertThat(statement.getHeader().getType().toString())
                .isEqualTo("swiyu-protected-issuance-authorization-trust-statement+jwt");
        assertThat(statement.getJWTClaimsSet().getSubject()).isEqualTo(issuerConfig.getIssuerDid());
        assertThat(statement.getJWTClaimsSet().getJSONObjectClaim("status")).containsKey("status_list");

        @SuppressWarnings("unchecked")
        Map<String, Object> canIssue = (Map<String, Object>) statement.getJWTClaimsSet().getClaim("can_issue");
        assertThat(canIssue)
                .containsEntry("vct", CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT)
                .containsEntry("vct_name", "Bound Example SD-JWT VC");
    }
}
