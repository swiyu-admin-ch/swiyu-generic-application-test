package ch.admin.bj.swiyu.swiyu_test_wallet.registry;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.support.TestConstants;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementRouteSupport.PROTECTED_VCT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class Tp2MockServerContractTest extends BaseTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().findAndRegisterModules();
    private static final String TP2_PROFILE_VERSION = "swiss-profile-trust:1.0.0";

    @Test
    @XrayTest(
            key = "EIDOMNI-1014",
            summary = "TP2 mock routes expose expected trust statement structures",
            description = """
                    This test validates that the TP2 mock registry endpoints expose the expected
                    list and statement structures used by issuer and verifier E2E flows.
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    void tp2MockRoutes_whenRequested_thenExposeExpectedListAndStatementStructures() throws Exception {
        RestClient client = mockServerRestClient();

        // Given / When
        String identityListBody = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v2/identity-trust-statement")
                        .queryParam("sub", issuerConfig.getIssuerDid())
                        .queryParam("page", 0)
                        .queryParam("size", 5)
                        .build())
                .retrieve()
                .body(String.class);

        String identityStatementBody = client.get()
                .uri("/api/v2/identity-trust-statement/{identifier}", issuerConfig.getIssuerDid())
                .retrieve()
                .body(String.class);

        String verificationListBody = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v2/verification-query-public-statement")
                        .queryParam("sub", verifierConfig.getVerifierDid())
                        .queryParam("filterActive", true)
                        .queryParam("page", 0)
                        .queryParam("size", 5)
                        .build())
                .retrieve()
                .body(String.class);

        String verificationStatementJti = "07f289d5-8b1f-4604-bf72-53bdcb71ee05";
        String verificationStatementBody = client.get()
                .uri("/api/v2/verification-query-public-statement/{jti}", verificationStatementJti)
                .retrieve()
                .body(String.class);

        String tmsRegistrationBody = client.post()
                .uri("/api/v1/trust/vqps-submissions")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer access_token")
                .body(tmsRegistrationRequest())
                .retrieve()
                .body(String.class);

        String protectedVerificationAuthorizationListBody = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v2/protected-verification-authorization-trust-statement")
                        .queryParam("sub", verifierConfig.getVerifierDid())
                        .queryParam("filterActive", true)
                        .queryParam("page", 0)
                        .queryParam("size", 1)
                        .build())
                .retrieve()
                .body(String.class);

        String protectedVerificationAuthorizationJti = "a8b1110d-f7c5-46da-9db1-8f4c89e8ff0d";
        String protectedVerificationAuthorizationBody = client.get()
                .uri("/api/v2/protected-verification-authorization-trust-statement/{jti}",
                        protectedVerificationAuthorizationJti)
                .retrieve()
                .body(String.class);

        String issuanceAuthorizationBody = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v2/protected-issuance-authorization-trust-statement")
                        .queryParam("sub", issuerConfig.getIssuerDid())
                        .queryParam("filterActive", true)
                        .queryParam("page", 0)
                        .queryParam("size", 1)
                        .build())
                .retrieve()
                .body(String.class);

        String protectedIssuanceAuthorizationJti = "d6ce2b08-e91d-4504-8fe3-0f214465db25";
        String protectedIssuanceAuthorizationStatementBody = client.get()
                .uri("/api/v2/protected-issuance-authorization-trust-statement/{jti}",
                        protectedIssuanceAuthorizationJti)
                .retrieve()
                .body(String.class);

        String protectedIssuanceTrustListStatementListBody = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v2/protected-issuance-trust-list-statement")
                        .queryParam("filterActive", true)
                        .queryParam("page", 0)
                        .queryParam("size", 1)
                        .build())
                .retrieve()
                .body(String.class);

        String protectedIssuanceTrustListJti = "fd841f09-e413-4ef3-9db2-9c1d7538c3a1";
        String protectedIssuanceTrustListStatementBody = client.get()
                .uri("/api/v2/protected-issuance-trust-list-statement/{jti}", protectedIssuanceTrustListJti)
                .retrieve()
                .body(String.class);

        String protectedIssuanceTrustListBody = client.get()
                .uri("/api/v2/protected-issuance-trust-list")
                .retrieve()
                .body(String.class);

        String nonComplianceTrustListBody = client.get()
                .uri("/api/v2/non-compliance-trust-list")
                .retrieve()
                .body(String.class);

        String trustStatusListBody = client.get()
                .uri("/api/v1/statuslist/tp2-trust-statements.jwt")
                .retrieve()
                .body(String.class);

        // Then
        assertIdentityTrustStatementList(identityListBody);
        assertIdentityTrustStatement(identityStatementBody);
        assertVerificationQueryPublicStatementList(verificationListBody);
        assertVerificationQueryPublicStatement(verificationStatementBody, verificationStatementJti);
        assertTmsRegistrationResponse(tmsRegistrationBody);
        assertProtectedVerificationAuthorizationList(protectedVerificationAuthorizationListBody);
        assertProtectedVerificationAuthorizationStatement(
                protectedVerificationAuthorizationBody,
                protectedVerificationAuthorizationJti
        );
        assertProtectedIssuanceAuthorizationList(issuanceAuthorizationBody);
        assertProtectedIssuanceAuthorizationStatement(
                protectedIssuanceAuthorizationStatementBody,
                protectedIssuanceAuthorizationJti
        );
        assertProtectedIssuanceTrustListStatementList(protectedIssuanceTrustListStatementListBody);
        assertProtectedIssuanceTrustListStatement(protectedIssuanceTrustListStatementBody, protectedIssuanceTrustListJti);
        assertProtectedIssuanceTrustList(protectedIssuanceTrustListBody);
        assertNonComplianceTrustList(nonComplianceTrustListBody);
        assertTrustStatusList(trustStatusListBody);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1166",
            summary = "TP2 read-only trust registry routes do not require Basic Auth",
            description = """
                    This test validates that read-only TP2 trust registry routes can be
                    consumed without the removed Trust Registry customer key/secret Basic Auth.
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    void tp2ReadOnlyRoutes_whenAuthorizationHeaderMissing_thenExposeTrustStatements() throws Exception {
        RestClient client = mockServerRestClient();

        // Given / When
        String identityListBody = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v2/identity-trust-statement")
                        .queryParam("sub", issuerConfig.getIssuerDid())
                        .build())
                .retrieve()
                .body(String.class);

        String protectedIssuanceAuthorizationListBody = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v2/protected-issuance-authorization-trust-statement")
                        .queryParam("sub", issuerConfig.getIssuerDid())
                        .build())
                .retrieve()
                .body(String.class);

        String protectedVerificationAuthorizationListBody = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v2/protected-verification-authorization-trust-statement")
                        .queryParam("sub", verifierConfig.getVerifierDid())
                        .build())
                .retrieve()
                .body(String.class);

        // Then
        assertIdentityTrustStatementList(identityListBody);
        assertProtectedIssuanceAuthorizationList(protectedIssuanceAuthorizationListBody);
        assertProtectedVerificationAuthorizationList(protectedVerificationAuthorizationListBody);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1167",
            summary = "TP2 TMS registration rejects requests without authorization or DCQL VCT metadata",
            description = """
                    This test validates that the TP2 TMS registration mock enforces the
                    expected authorization header and rejects DCQL registration payloads
                    whose credential metadata does not provide vct_values.
                    """)
    void tmsRegistration_whenAuthorizationOrDcqlMetadataMissing_thenRejectsRequest() {
        RestClient client = mockServerRestClient();

        // Given
        Map<String, Object> invalidRegistration = tmsRegistrationRequestWithoutVctValues();

        // When / Then
        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.post()
                        .uri("/api/v1/trust/vqps-submissions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(tmsRegistrationRequest())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(401);
                    assertThat(exception.getResponseBodyAsString()).contains("OAuth access token is required");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.post()
                        .uri("/api/v1/trust/vqps-submissions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer access_token")
                        .body(invalidRegistration)
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString())
                            .contains("\"status\":\"error\"")
                            .contains("query.credentials.meta.vct_values must be a non-empty array");
                });
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1168",
            summary = "TP2 mock routes reject malformed registry queries and return empty unknown results",
            description = """
                    This test validates that TP2 mock registry list routes return empty
                    paged results for unknown identifiers and reject malformed query
                    parameters or invalid statement identifiers with the expected errors.
                    """)
    void tp2MockRoutes_whenMalformedOrUnknownRegistryQueries_thenRejectOrReturnEmptyResults() throws Exception {
        RestClient client = mockServerRestClient();

        // Given / When
        String defaultProtectedIssuanceTrustListStatementListBody = client.get()
                .uri("/api/v2/protected-issuance-trust-list-statement")
                .retrieve()
                .body(String.class);

        String defaultProtectedIssuanceAuthorizationListBody = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v2/protected-issuance-authorization-trust-statement")
                        .queryParam("sub", issuerConfig.getIssuerDid())
                        .build())
                .retrieve()
                .body(String.class);

        String unknownProtectedIssuanceAuthorizationListBody = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v2/protected-issuance-authorization-trust-statement")
                        .queryParam("sub", "did:tdw:QmUnknown:identifier.admin.ch:api:v1:did")
                        .queryParam("filterActive", false)
                        .queryParam("page", 0)
                        .queryParam("size", 5)
                        .build())
                .retrieve()
                .body(String.class);

        String defaultProtectedVerificationAuthorizationListBody = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v2/protected-verification-authorization-trust-statement")
                        .queryParam("sub", verifierConfig.getVerifierDid())
                        .build())
                .retrieve()
                .body(String.class);

        String unknownProtectedVerificationAuthorizationListBody = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v2/protected-verification-authorization-trust-statement")
                        .queryParam("sub", "did:tdw:QmUnknown:identifier.admin.ch:api:v1:did")
                        .queryParam("filterActive", false)
                        .queryParam("page", 0)
                        .queryParam("size", 5)
                        .build())
                .retrieve()
                .body(String.class);

        String defaultVerificationListBody = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v2/verification-query-public-statement")
                        .queryParam("sub", verifierConfig.getVerifierDid())
                        .build())
                .retrieve()
                .body(String.class);

        String unknownVerificationListBody = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v2/verification-query-public-statement")
                        .queryParam("sub", "did:tdw:QmUnknown:identifier.admin.ch:api:v1:did")
                        .queryParam("filterActive", false)
                        .queryParam("page", 0)
                        .queryParam("size", 5)
                        .build())
                .retrieve()
                .body(String.class);

        String defaultIdentityListBody = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v2/identity-trust-statement")
                        .queryParam("sub", issuerConfig.getIssuerDid())
                        .build())
                .retrieve()
                .body(String.class);

        String unknownIdentityListBody = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v2/identity-trust-statement")
                        .queryParam("sub", "did:tdw:QmUnknown:identifier.admin.ch:api:v1:did")
                        .queryParam("filterActive", false)
                        .queryParam("page", 0)
                        .queryParam("size", 5)
                        .build())
                .retrieve()
                .body(String.class);

        // Then
        assertProtectedIssuanceTrustListStatementList(defaultProtectedIssuanceTrustListStatementListBody);
        assertProtectedIssuanceAuthorizationList(defaultProtectedIssuanceAuthorizationListBody);
        assertEmptyPagedContent(unknownProtectedIssuanceAuthorizationListBody, 0);
        assertProtectedVerificationAuthorizationList(defaultProtectedVerificationAuthorizationListBody);
        assertEmptyPagedContent(unknownProtectedVerificationAuthorizationListBody, 0);
        assertVerificationQueryPublicStatementList(defaultVerificationListBody);
        assertEmptyPagedContent(unknownVerificationListBody, 0);
        assertIdentityTrustStatementList(defaultIdentityListBody);
        assertEmptyPagedContent(unknownIdentityListBody, 0);

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri(uriBuilder -> uriBuilder
                                .path("/api/v2/identity-trust-statement")
                                .queryParam("filterActive", "maybe")
                                .build())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("filterActive must be a boolean");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri(uriBuilder -> uriBuilder
                                .path("/api/v2/protected-issuance-authorization-trust-statement")
                                .queryParam("filterActive", "maybe")
                                .build())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("filterActive must be a boolean");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri(uriBuilder -> uriBuilder
                                .path("/api/v2/protected-issuance-authorization-trust-statement")
                                .queryParam("page", "abc")
                                .build())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("page must be a non-negative integer");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri(uriBuilder -> uriBuilder
                                .path("/api/v2/protected-issuance-authorization-trust-statement")
                                .queryParam("size", 0)
                                .build())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("size must be a positive integer");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri(uriBuilder -> uriBuilder
                                .path("/api/v2/protected-verification-authorization-trust-statement")
                                .queryParam("filterActive", "maybe")
                                .build())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("filterActive must be a boolean");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri(uriBuilder -> uriBuilder
                                .path("/api/v2/protected-verification-authorization-trust-statement")
                                .queryParam("page", "abc")
                                .build())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("page must be a non-negative integer");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri(uriBuilder -> uriBuilder
                                .path("/api/v2/protected-verification-authorization-trust-statement")
                                .queryParam("size", 0)
                                .build())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("size must be a positive integer");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri(uriBuilder -> uriBuilder
                                .path("/api/v2/verification-query-public-statement")
                                .queryParam("filterActive", "maybe")
                                .build())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("filterActive must be a boolean");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri(uriBuilder -> uriBuilder
                                .path("/api/v2/verification-query-public-statement")
                                .queryParam("page", "abc")
                                .build())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("page must be a non-negative integer");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri(uriBuilder -> uriBuilder
                                .path("/api/v2/verification-query-public-statement")
                                .queryParam("size", 0)
                                .build())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("size must be a positive integer");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri(uriBuilder -> uriBuilder
                                .path("/api/v2/identity-trust-statement")
                                .queryParam("page", "abc")
                                .build())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("page must be a non-negative integer");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri(uriBuilder -> uriBuilder
                                .path("/api/v2/identity-trust-statement")
                                .queryParam("size", 0)
                                .build())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("size must be a positive integer");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri(uriBuilder -> uriBuilder
                                .path("/api/v2/protected-issuance-trust-list-statement")
                                .queryParam("filterActive", "maybe")
                                .build())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("filterActive must be a boolean");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri(uriBuilder -> uriBuilder
                                .path("/api/v2/protected-issuance-trust-list-statement")
                                .queryParam("page", "abc")
                                .build())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("page must be a non-negative integer");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri(uriBuilder -> uriBuilder
                                .path("/api/v2/protected-issuance-trust-list-statement")
                                .queryParam("size", 0)
                                .build())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("size must be a positive integer");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri(uriBuilder -> uriBuilder
                                .path("/api/v2/protected-issuance-trust-list-statement")
                                .queryParam("sub", issuerConfig.getIssuerDid())
                                .build())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("sub is not supported");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri("/api/v2/protected-issuance-trust-list-statement/{jti}", "not-a-uuid")
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("jti must be a UUIDv4");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri("/api/v2/protected-issuance-authorization-trust-statement/{jti}", "not-a-uuid")
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("jti must be a UUIDv4");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri("/api/v2/protected-verification-authorization-trust-statement/{jti}", "not-a-uuid")
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("jti must be a UUIDv4");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri("/api/v2/verification-query-public-statement/{jti}", "not-a-uuid")
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> {
                    assertThat(exception.getStatusCode().value()).isEqualTo(400);
                    assertThat(exception.getResponseBodyAsString()).contains("jti must be a UUIDv4");
                });

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri("/api/v2/identity-trust-statement/{identifier}",
                                "did:tdw:QmUnknown:identifier.admin.ch:api:v1:did")
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> assertThat(exception.getStatusCode().value()).isEqualTo(404));

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri("/api/v2/protected-issuance-trust-list-statement/{jti}", UUID.randomUUID())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> assertThat(exception.getStatusCode().value()).isEqualTo(404));

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri("/api/v2/protected-issuance-authorization-trust-statement/{jti}", UUID.randomUUID())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> assertThat(exception.getStatusCode().value()).isEqualTo(404));

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri("/api/v2/protected-verification-authorization-trust-statement/{jti}", UUID.randomUUID())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> assertThat(exception.getStatusCode().value()).isEqualTo(404));

        assertThatExceptionOfType(RestClientResponseException.class)
                .isThrownBy(() -> client.get()
                        .uri("/api/v2/verification-query-public-statement/{jti}", UUID.randomUUID())
                        .retrieve()
                        .body(String.class))
                .satisfies(exception -> assertThat(exception.getStatusCode().value()).isEqualTo(404));
    }

    private RestClient mockServerRestClient() {
        return RestClient.builder()
                .baseUrl("http://%s:%d".formatted(
                        mockServerContainer.getHost(),
                        mockServerContainer.getMappedPort(1080)
                ))
                .build();
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
                .containsEntry("size", 1)
                .containsEntry("number", 0)
                .containsEntry("totalPages", 1)
                .containsEntry("totalElements", 1);

        SignedJWT statement = SignedJWT.parse(content.getFirst());
        assertTrustStatementHeader(statement, "swiyu-identity-trust-statement+jwt");
        assertThat(statement.getJWTClaimsSet().getIssuer()).isNull();
        assertThat(statement.getJWTClaimsSet().getJWTID()).isNull();
        assertThat(statement.getJWTClaimsSet().getIssueTime()).isNotNull();
        assertThat(statement.getJWTClaimsSet().getNotBeforeTime()).isNotNull();
        assertThat(statement.getJWTClaimsSet().getExpirationTime()).isNotNull();
        assertThat(statement.getJWTClaimsSet().getSubject()).isEqualTo(issuerConfig.getIssuerDid());
        assertThat(statement.getJWTClaimsSet().getStringClaim("entity_name")).isEqualTo("Mock TP2 Issuer");
        assertThat(statement.getJWTClaimsSet().getStringClaim("entity_name#en")).isEqualTo("Mock TP2 Issuer");
        assertThat(statement.getJWTClaimsSet().getStringClaim("entity_name#de-CH")).isEqualTo("Mock TP2 Issuer Schweiz");
        assertThat(statement.getJWTClaimsSet().getBooleanClaim("is_state_actor")).isTrue();
        assertThat(statement.getJWTClaimsSet().getJSONObjectClaim("status")).containsKey("status_list");
        assertThat(statement.getJWTClaimsSet().getClaim("registry_ids"))
                .isEqualTo(List.of(
                        Map.of("type", "UID", "value", "CHE-123.456.789"),
                        Map.of("type", "LEI", "value", "0A1B2C3D4E5F6G7H8J9I")
                ));
    }

    private void assertIdentityTrustStatement(String jwt) throws ParseException {
        SignedJWT statement = SignedJWT.parse(jwt);

        assertTrustStatementHeader(statement, "swiyu-identity-trust-statement+jwt");
        assertThat(statement.getJWTClaimsSet().getSubject()).isEqualTo(issuerConfig.getIssuerDid());
        assertThat(statement.getJWTClaimsSet().getStringClaim("entity_name")).isEqualTo("Mock TP2 Issuer");
        assertThat(statement.getJWTClaimsSet().getStringClaim("entity_name#en")).isEqualTo("Mock TP2 Issuer");
        assertThat(statement.getJWTClaimsSet().getStringClaim("entity_name#de-CH")).isEqualTo("Mock TP2 Issuer Schweiz");
    }

    private void assertVerificationQueryPublicStatementList(String responseBody) throws Exception {
        Map<String, Object> response = OBJECT_MAPPER.readValue(responseBody, new TypeReference<>() {
        });
        @SuppressWarnings("unchecked")
        List<String> content = (List<String>) response.get("content");
        @SuppressWarnings("unchecked")
        Map<String, Object> page = (Map<String, Object>) response.get("page");

        assertThat(content).isNotEmpty();
        assertThat(page)
                .containsEntry("size", content.size())
                .containsEntry("number", 0)
                .containsEntry("totalPages", 1)
                .containsEntry("totalElements", content.size());

        String defaultStatement = null;
        for (String jwt : content) {
            SignedJWT statement = SignedJWT.parse(jwt);
            if ("07f289d5-8b1f-4604-bf72-53bdcb71ee05".equals(statement.getJWTClaimsSet().getJWTID())) {
                defaultStatement = jwt;
                break;
            }
        }

        assertThat(defaultStatement)
                .as("Default verification query public statement must remain in the TMS list response")
                .isNotNull();
        assertVerificationQueryPublicStatement(defaultStatement, "07f289d5-8b1f-4604-bf72-53bdcb71ee05");
    }

    private void assertVerificationQueryPublicStatement(String jwt, String expectedJti) throws ParseException {
        SignedJWT statement = SignedJWT.parse(jwt);

        assertTrustStatementHeader(statement, "swiyu-verification-query-public-statement+jwt");
        assertThat(statement.getJWTClaimsSet().getJWTID()).isEqualTo(expectedJti);
        assertThat(statement.getJWTClaimsSet().getSubject()).isEqualTo(verifierConfig.getVerifierDid());
        assertThat(statement.getJWTClaimsSet().getStringClaim("purpose_name")).isEqualTo("Employment check");
        assertThat(statement.getJWTClaimsSet().getStringClaim("purpose_name#en")).isEqualTo("Employment check");
        assertThat(statement.getJWTClaimsSet().getStringClaim("purpose_name#de-CH")).isEqualTo("Beschaeftigungspruefung");
        assertThat(statement.getJWTClaimsSet().getStringClaim("purpose_description"))
                .isEqualTo("Mock TP2 verification request used by application tests.");
        assertThat(statement.getJWTClaimsSet().getStringClaim("purpose_description#en"))
                .isEqualTo("Mock TP2 verification request used by application tests.");
        assertThat(statement.getJWTClaimsSet().getStringClaim("purpose_description#de-CH"))
                .isEqualTo("Mock-TP2-Verifizierungsanfrage fuer Anwendungstests.");

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
        assertProtectedVctValues(meta.get("vct_values"));
    }

    private void assertTmsRegistrationResponse(String responseBody) throws Exception {
        Map<String, Object> response = OBJECT_MAPPER.readValue(responseBody, new TypeReference<>() {
        });
        @SuppressWarnings("unchecked")
        Map<String, Object> publicationResult = (Map<String, Object>) response.get("publicationResult");

        assertThat(response.get("id")).isInstanceOf(String.class);
        assertThat(response.get("partnerId")).isInstanceOf(String.class);
        assertThat(response).containsEntry("version", 1)
                .containsEntry("status", "PUBLICATION_SUCCEEDED");
        assertThat(response.get("createdAt")).isInstanceOf(String.class);
        assertThat(response.get("updatedAt")).isInstanceOf(String.class);

        assertUuidV4((String) response.get("id"));
        assertUuidV4((String) response.get("partnerId"));
        assertUuidV4((String) publicationResult.get("jti"));
        assertThat(publicationResult.get("jwt")).isInstanceOf(String.class);
        assertThat(publicationResult.get("expiresAt")).isInstanceOf(String.class);

        SignedJWT statement = SignedJWT.parse((String) publicationResult.get("jwt"));
        assertTrustStatementHeader(statement, "swiyu-verification-query-public-statement+jwt");
        assertThat(publicationResult.get("jti")).isEqualTo(statement.getJWTClaimsSet().getJWTID());
        assertThat(Instant.parse((String) publicationResult.get("expiresAt")))
                .isEqualTo(statement.getJWTClaimsSet().getExpirationTime().toInstant());
        assertThat(statement.getJWTClaimsSet().getSubject()).isEqualTo(verifierConfig.getVerifierDid());
        assertThat(statement.getJWTClaimsSet().getJWTID()).satisfies(this::assertUuidV4);
        assertThat(statement.getJWTClaimsSet().getStringClaim("purpose_name")).isEqualTo("Age verification");
        assertThat(statement.getJWTClaimsSet().getStringClaim("purpose_name#en")).isEqualTo("Age verification");
        assertThat(statement.getJWTClaimsSet().getStringClaim("purpose_description"))
                .isEqualTo("Verification of age for purchasing restricted goods");
        assertThat(statement.getJWTClaimsSet().getStringClaim("purpose_description#en"))
                .isEqualTo("Verification of age for purchasing restricted goods");

        @SuppressWarnings("unchecked")
        Map<String, Object> request = (Map<String, Object>) statement.getJWTClaimsSet().getClaim("request");
        @SuppressWarnings("unchecked")
        Map<String, Object> query = (Map<String, Object>) request.get("query");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) query.get("credentials");
        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) credentials.getFirst().get("meta");
        assertThat(request).containsEntry("type", "DCQL")
                .containsEntry("scope", "com.example.age_verification_presentation");
        assertProtectedVctValues(meta.get("vct_values"));
    }

    private void assertProtectedIssuanceAuthorizationList(String responseBody) throws Exception {
        Map<String, Object> response = OBJECT_MAPPER.readValue(responseBody, new TypeReference<>() {
        });
        @SuppressWarnings("unchecked")
        List<String> content = (List<String>) response.get("content");
        @SuppressWarnings("unchecked")
        Map<String, Object> page = (Map<String, Object>) response.get("page");

        assertThat(content).hasSize(1);
        assertThat(page)
                .containsEntry("size", 1)
                .containsEntry("number", 0)
                .containsEntry("totalPages", 1)
                .containsEntry("totalElements", 1);

        SignedJWT statement = SignedJWT.parse(content.getFirst());
        assertTrustStatementHeader(statement, "swiyu-protected-issuance-authorization-trust-statement+jwt");
        assertThat(statement.getJWTClaimsSet().getSubject()).isEqualTo(issuerConfig.getIssuerDid());
        assertThat(statement.getJWTClaimsSet().getJWTID()).satisfies(this::assertUuidV4);
        assertThat(statement.getJWTClaimsSet().getJSONObjectClaim("status")).containsKey("status_list");

        @SuppressWarnings("unchecked")
        Map<String, Object> canIssue = (Map<String, Object>) statement.getJWTClaimsSet().getClaim("can_issue");
        assertThat(canIssue)
                .containsEntry("vct", PROTECTED_VCT)
                .containsEntry("vct_name", "Bound Example SD-JWT VC")
                .containsEntry("reason", "Protected example issuance.");
        assertProtectedVctUrl((String) canIssue.get("vct"));
    }

    private void assertProtectedVerificationAuthorizationList(String responseBody) throws Exception {
        Map<String, Object> response = OBJECT_MAPPER.readValue(responseBody, new TypeReference<>() {
        });
        @SuppressWarnings("unchecked")
        List<String> content = (List<String>) response.get("content");
        @SuppressWarnings("unchecked")
        Map<String, Object> page = (Map<String, Object>) response.get("page");

        assertThat(content).hasSize(1);
        assertThat(page)
                .containsEntry("size", 1)
                .containsEntry("number", 0)
                .containsEntry("totalPages", 1)
                .containsEntry("totalElements", 1);
        assertProtectedVerificationAuthorizationStatement(
                content.getFirst(),
                "a8b1110d-f7c5-46da-9db1-8f4c89e8ff0d"
        );
    }

    private void assertProtectedVerificationAuthorizationStatement(String jwt, String expectedJti) throws ParseException {
        SignedJWT statement = SignedJWT.parse(jwt);

        assertTrustStatementHeader(statement, "swiyu-protected-verification-authorization-trust-statement+jwt");
        assertThat(statement.getJWTClaimsSet().getSubject()).isEqualTo(verifierConfig.getVerifierDid());
        assertThat(statement.getJWTClaimsSet().getJWTID()).isEqualTo(expectedJti);
        assertThat(statement.getJWTClaimsSet().getClaim("authorized_fields"))
                .isEqualTo(List.of("personal_administrative_number"));
    }

    private void assertProtectedIssuanceAuthorizationStatement(String jwt, String expectedJti) throws ParseException {
        SignedJWT statement = SignedJWT.parse(jwt);

        assertTrustStatementHeader(statement, "swiyu-protected-issuance-authorization-trust-statement+jwt");
        assertThat(statement.getJWTClaimsSet().getSubject()).isEqualTo(issuerConfig.getIssuerDid());
        assertThat(statement.getJWTClaimsSet().getJWTID()).isEqualTo(expectedJti);
        @SuppressWarnings("unchecked")
        Map<String, Object> canIssue = (Map<String, Object>) statement.getJWTClaimsSet().getClaim("can_issue");
        assertThat(canIssue)
                .containsEntry("vct", PROTECTED_VCT)
                .containsEntry("reason", "Protected example issuance.");
        assertProtectedVctUrl((String) canIssue.get("vct"));
    }

    private void assertProtectedIssuanceTrustListStatementList(String responseBody) throws Exception {
        Map<String, Object> response = OBJECT_MAPPER.readValue(responseBody, new TypeReference<>() {
        });
        @SuppressWarnings("unchecked")
        List<String> content = (List<String>) response.get("content");
        @SuppressWarnings("unchecked")
        Map<String, Object> page = (Map<String, Object>) response.get("page");

        assertThat(content).hasSize(1);
        assertThat(page)
                .containsEntry("size", 1)
                .containsEntry("number", 0)
                .containsEntry("totalPages", 1)
                .containsEntry("totalElements", 1);
        assertProtectedIssuanceTrustListStatement(content.getFirst(), "fd841f09-e413-4ef3-9db2-9c1d7538c3a1");
    }

    private void assertProtectedIssuanceTrustListStatement(String jwt, String expectedJti) throws ParseException {
        SignedJWT statement = SignedJWT.parse(jwt);

        assertTrustStatementHeader(statement, "swiyu-protected-issuance-trust-list-statement+jwt");
        assertThat(statement.getJWTClaimsSet().getJWTID()).isEqualTo(expectedJti);
        assertProtectedVctValues(statement.getJWTClaimsSet().getClaim("vct_values"));
    }

    private void assertProtectedIssuanceTrustList(String jwt) throws ParseException {
        SignedJWT statement = SignedJWT.parse(jwt);

        assertTrustStatementHeader(statement, "swiyu-protected-issuance-trust-list-statement+jwt");
        assertThat(statement.getJWTClaimsSet().getSubject()).isNull();
        assertThat(statement.getJWTClaimsSet().getJWTID()).satisfies(this::assertUuidV4);
        assertProtectedVctValues(statement.getJWTClaimsSet().getClaim("vct_values"));
    }

    private void assertNonComplianceTrustList(String jwt) throws ParseException {
        SignedJWT statement = SignedJWT.parse(jwt);

        assertTrustStatementHeader(statement, "swiyu-non-compliance-trust-list-statement+jwt");
        assertThat(statement.getJWTClaimsSet().getSubject()).isNull();
        assertThat(statement.getJWTClaimsSet().getJSONObjectClaim("status")).containsKey("status_list");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> actors = (List<Map<String, Object>>) statement.getJWTClaimsSet().getClaim("non_compliant_actors");
        assertThat(actors).hasSize(2);
        assertThat(actors.getFirst())
                .containsEntry("actor", "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRCC1:identifier.admin.ch:api:v1:did")
                .containsEntry("flagged_at", "2026-02-25T07:07:35Z")
                .containsEntry("reason", "Mock bad actor entry used by application tests.")
                .containsEntry("reason#de", "Mock bad actor entry used by application tests. (DE)")
                .containsEntry("reason#en", "Mock bad actor entry used by application tests. (EN)")
                .containsEntry("reason#fr-CH", "Mock bad actor entry used by application tests. (FR)")
                .containsEntry("reason#it-CH", "Mock bad actor entry used by application tests. (IT)")
                .containsEntry("reason#rm-CH", "Mock bad actor entry used by application tests. (RM)");
        assertThat(actors.get(1))
                .containsEntry("actor", verifierConfig.getVerifierDid())
                .containsEntry("flagged_at", "2025-01-13T07:13:00Z")
                .containsEntry("reason", "Mock verifier non-compliance entry used by application tests.")
                .containsEntry("reason#en", "Mock verifier non-compliance entry used by application tests. (EN)");
    }

    private void assertTrustStatusList(String jwt) throws ParseException {
        SignedJWT statusList = SignedJWT.parse(jwt);

        assertThat(statusList.getHeader().getType().toString()).isEqualTo("statuslist+jwt");
        assertThat(statusList.getHeader().getKeyID()).isEqualTo(trustConfig.getTrustAssertKeyId());
        assertThat(statusList.getHeader().getCustomParam("profile_version")).isNull();
        assertThat(statusList.getJWTClaimsSet().getIssuer()).isEqualTo(trustConfig.getTrustDid());
        assertThat(statusList.getJWTClaimsSet().getJSONObjectClaim("status_list")).containsKeys("bits", "lst");
    }

    private void assertUuidV4(String value) {
        assertThat(java.util.UUID.fromString(value).version()).isEqualTo(4);
    }

    private void assertTrustStatementHeader(SignedJWT statement, String expectedType) {
        assertThat(statement.getHeader().getType().toString()).isEqualTo(expectedType);
        assertThat(statement.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
        assertThat(statement.getHeader().getKeyID()).isEqualTo(trustConfig.getTrustAssertKeyId());
        assertThat(statement.getHeader().getCustomParam("profile_version")).isEqualTo(TP2_PROFILE_VERSION);
    }

    private void assertProtectedVctUrl(String vct) {
        assertThat(vct)
                .isEqualTo(PROTECTED_VCT)
                .startsWith(TestConstants.ISSUER_URL + "/oid4vci/vct/");
    }

    private void assertProtectedVctValues(Object vctValues) {
        assertThat(vctValues).isEqualTo(List.of(PROTECTED_VCT));
        assertProtectedVctUrl((String) ((List<?>) vctValues).getFirst());
    }

    private void assertEmptyPagedContent(String responseBody, int expectedPageNumber) throws Exception {
        Map<String, Object> response = OBJECT_MAPPER.readValue(responseBody, new TypeReference<>() {
        });
        @SuppressWarnings("unchecked")
        List<String> content = (List<String>) response.get("content");
        @SuppressWarnings("unchecked")
        Map<String, Object> page = (Map<String, Object>) response.get("page");

        assertThat(content).isEmpty();
        assertThat(page)
                .containsEntry("size", 0)
                .containsEntry("number", expectedPageNumber)
                .containsEntry("totalPages", 0)
                .containsEntry("totalElements", 0);
    }

    private Map<String, Object> tmsRegistrationRequest() {
        return Map.of(
                "sub", verifierConfig.getVerifierDid(),
                "purpose_name", "Age verification",
                "purpose_name#en", "Age verification",
                "purpose_description", "Verification of age for purchasing restricted goods",
                "purpose_description#en", "Verification of age for purchasing restricted goods",
                "scope", "com.example.age_verification_presentation",
                "query", Map.of(
                        "credentials", List.of(Map.of(
                                "id", "age-verification",
                                "format", "dc+sd-jwt",
                                "meta", Map.of(
                                        "vct_values", List.of(PROTECTED_VCT)
                                ),
                                "claims", List.of(Map.of("path", List.of("birth_date")))
                        ))
                )
        );
    }

    private Map<String, Object> tmsRegistrationRequestWithoutVctValues() {
        return Map.of(
                "sub", verifierConfig.getVerifierDid(),
                "purpose_name", "Age verification",
                "purpose_name#en", "Age verification",
                "purpose_description", "Verification of age for purchasing restricted goods",
                "purpose_description#en", "Verification of age for purchasing restricted goods",
                "scope", "com.example.age_verification_presentation",
                "query", Map.of(
                        "credentials", List.of(Map.of(
                                "id", "age-verification",
                                "format", "dc+sd-jwt",
                                "meta", Map.of("vct_values", List.of()),
                                "claims", List.of(Map.of("path", List.of("birth_date")))
                        ))
                )
        );
    }
}
