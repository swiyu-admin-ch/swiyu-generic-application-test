package ch.admin.bj.swiyu.swiyu_test_wallet.security;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseVerifiers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.MANAGEMENT_KEYCLOAK)
@UseVerifiers(VerifierVariant.MANAGEMENT_KEYCLOAK)
class KeycloakManagementAuthTest extends BaseTest {

    private static final String INVALID_BEARER_TOKEN =
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlLXVzZXIiLCJleHAiOjQ3MjM2NDgwMDB9.invalid-signature";
    private static final String MALFORMED_BEARER_TOKEN = "not-a-jwt";

    @Test
    @XrayTest(
            key = "EIDOMNI-1056",
            summary = "Issuer management endpoints are protected by Keycloak JWT authentication",
            description = """
                    This test validates that issuer OID4VCI metadata endpoints remain public while issuer management
                    credential and status-list endpoints reject missing or invalid bearer tokens and accept a valid
                    Keycloak client-credentials token.
                    """
    )
    @Tag(ReportingTags.UCI_S1)
    @Tag(ReportingTags.UCI_P1)
    @Tag(ReportingTags.EDGE_CASE)
    void issuerManagement_withKeycloakAuth_thenPublicMetadataAndProtectedManagementBehaveCorrectly() {
        // Given
        final String unknownId = UUID.randomUUID().toString();

        // Then
        assertOkGet(issuerUrl("/oid4vci/.well-known/openid-configuration"));
        assertOkGet(issuerUrl("/oid4vci/.well-known/oauth-authorization-server"));
        assertOkGet(issuerUrl("/oid4vci/.well-known/openid-credential-issuer"));

        assertUnauthorizedPost(issuerUrl("/management/api/credentials"));
        assertUnauthorizedGet(issuerUrl("/management/api/credentials/" + unknownId));
        assertUnauthorizedPost(issuerUrl("/management/api/status-list"));
        assertUnauthorizedGet(issuerUrl("/management/api/status-list/" + unknownId));

        assertUnauthorizedPostWithBearer(issuerUrl("/management/api/credentials"), INVALID_BEARER_TOKEN);
        assertUnauthorizedGetWithBearer(issuerUrl("/management/api/credentials/" + unknownId), INVALID_BEARER_TOKEN);
        assertUnauthorizedPostWithBearer(issuerUrl("/management/api/status-list"), INVALID_BEARER_TOKEN);
        assertUnauthorizedGetWithBearer(issuerUrl("/management/api/status-list/" + unknownId), INVALID_BEARER_TOKEN);

        // When
        final CredentialWithDeeplinkResponse credential = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT,
                CredentialSubjectFixtures.completeEmployeeProfile()
        );

        // Then
        assertThat(credential.getManagementId()).isNotNull();
        assertThat(issuerManager.getCredentialById(credential.getManagementId()).getStatus())
                .isEqualTo(CredentialStatusType.OFFERED);
        assertUnauthorizedGet(issuerUrl("/management/api/credentials/" + credential.getManagementId()));
        assertUnauthorizedGetWithBearer(
                issuerUrl("/management/api/credentials/" + credential.getManagementId()),
                INVALID_BEARER_TOKEN
        );
        assertUnauthorizedGet(issuerUrl("/management/api/status-list/" + getCurrentStatusList().getId()));
        assertUnauthorizedGetWithBearer(
                issuerUrl("/management/api/status-list/" + getCurrentStatusList().getId()),
                INVALID_BEARER_TOKEN
        );
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1094",
            summary = "Verifier management endpoints are protected by Keycloak JWT authentication",
            description = """
                    This test validates that verifier OID4VP wallet-facing metadata remains public while verifier
                    management endpoints reject missing or invalid bearer tokens and accept a valid Keycloak
                    client-credentials token.
                    """
    )
    @Tag(ReportingTags.UCV_M1)
    @Tag(ReportingTags.EDGE_CASE)
    void verifierManagement_withKeycloakAuth_thenPublicWalletEndpointsAndProtectedManagementBehaveCorrectly() {
        // Given
        final String unknownId = UUID.randomUUID().toString();

        // Then
        assertOkGet(verifierUrl("/oid4vp/api/openid-client-metadata.json"));

        assertUnauthorizedPost(verifierUrl("/management/api/verifications"));
        assertUnauthorizedGet(verifierUrl("/management/api/verifications/" + unknownId));
        assertUnauthorizedPostWithBearer(verifierUrl("/management/api/verifications"), INVALID_BEARER_TOKEN);
        assertUnauthorizedGetWithBearer(verifierUrl("/management/api/verifications/" + unknownId), INVALID_BEARER_TOKEN);

        // When
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(false)
                .createManagementResponse();

        // Then
        assertThat(verification.getId()).isNotNull();
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
        assertUnauthorizedGet(verifierUrl("/management/api/verifications/" + verification.getId()));
        assertUnauthorizedGetWithBearer(
                verifierUrl("/management/api/verifications/" + verification.getId()),
                INVALID_BEARER_TOKEN
        );
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1095",
            summary = "Management endpoints reject malformed authorization headers",
            description = """
                    This test validates that issuer and verifier management endpoints reject malformed or unsupported
                    Authorization headers when Keycloak JWT resource-server authentication is configured.
                    """
    )
    @Tag(ReportingTags.UCI_S1)
    @Tag(ReportingTags.UCV_M1)
    @Tag(ReportingTags.EDGE_CASE)
    void managementEndpoints_withMalformedAuthorizationHeaders_thenIssuerAndVerifierRejectRequests() {
        // Given
        final String statusListUrl = issuerUrl("/management/api/status-list/" + getCurrentStatusList().getId());
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(false)
                .createManagementResponse();
        final String verificationUrl = verifierUrl("/management/api/verifications/" + verification.getId());

        // Then
        assertAuthenticationRejectedGet(statusListUrl, "Basic dXNlcjpwYXNzd29yZA==");
        assertAuthenticationRejectedGet(statusListUrl, "Bearer");
        assertAuthenticationRejectedGet(statusListUrl, "Bearer ");
        assertAuthenticationRejectedGet(statusListUrl, "Bearer " + MALFORMED_BEARER_TOKEN);

        assertAuthenticationRejectedGet(verificationUrl, "Basic dXNlcjpwYXNzd29yZA==");
        assertAuthenticationRejectedGet(verificationUrl, "Bearer");
        assertAuthenticationRejectedGet(verificationUrl, "Bearer ");
        assertAuthenticationRejectedGet(verificationUrl, "Bearer " + MALFORMED_BEARER_TOKEN);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1096",
            summary = "Issuer and verifier workflow succeeds with Keycloak-protected management APIs",
            description = """
                    This test validates that authenticated management calls can create an issuer credential offer and a
                    verifier verification request while wallet-facing OID4VCI and OID4VP endpoints remain usable for a
                    complete issuance and presentation workflow.
                    """
    )
    @Tag(ReportingTags.UCI_C1A)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.HAPPY_PATH)
    void securedIssuerVerifierFlow_withKeycloakManagementAuth_thenWalletCanCompleteVerification() {
        // Given
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT,
                CredentialSubjectFixtures.completeEmployeeProfile()
        );
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final String verifiableCredential = batchEntry.getIssuedCredentials().getFirst();

        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(false)
                .createManagementResponse();
        final RequestObject verificationDetails = wallet.getVerificationRequestObject(
                verification.getVerificationDeeplink()
        );
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

        // When
        wallet.setUseEncryption(false);
        wallet.respondToVerification(verificationDetails, verifiableCredential);

        // Then
        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
        assertUnauthorizedGet(verifierUrl("/management/api/verifications/" + verification.getId()));
        assertUnauthorizedGetWithBearer(
                verifierUrl("/management/api/verifications/" + verification.getId()),
                INVALID_BEARER_TOKEN
        );
    }

    private String issuerUrl(String path) {
        return issuerConfig.getIssuerServiceUrl() + path;
    }

    private String verifierUrl(String path) {
        return "http://%s:%d%s".formatted(
                verifierContainer.getHost(),
                verifierContainer.getMappedPort(8080),
                path
        );
    }

    private void assertOkGet(String url) {
        assertThat(restClient.get()
                .uri(url)
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .toBodilessEntity()
                .getStatusCode()
                .value()).isEqualTo(200);
    }

    private void assertUnauthorizedGet(String url) {
        assertUnauthorized(() -> restClient.get()
                .uri(url)
                .retrieve()
                .toBodilessEntity());
    }

    private void assertUnauthorizedGetWithBearer(String url, String token) {
        assertUnauthorized(() -> restClient.get()
                .uri(url)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .toBodilessEntity());
    }

    private void assertAuthenticationRejectedGet(String url, String authorizationHeader) {
        assertThatThrownBy(() -> restClient.get()
                .uri(url)
                .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                .retrieve()
                .toBodilessEntity())
                .isInstanceOfSatisfying(HttpClientErrorException.class, ex ->
                        assertThat(errorCode(ex)).isIn(400, 401));
    }

    private void assertUnauthorizedPost(String url) {
        assertUnauthorized(() -> restClient.post()
                .uri(url)
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of())
                .retrieve()
                .toBodilessEntity());
    }

    private void assertUnauthorizedPostWithBearer(String url, String token) {
        assertUnauthorized(() -> restClient.post()
                .uri(url)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of())
                .retrieve()
                .toBodilessEntity());
    }

    private void assertUnauthorized(Runnable request) {
        assertThatThrownBy(request::run)
                .isInstanceOfSatisfying(HttpClientErrorException.class, ex ->
                        assertThat(errorCode(ex)).isEqualTo(401));
    }
}
