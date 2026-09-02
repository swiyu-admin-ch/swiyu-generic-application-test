package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.CredentialEvaluation;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseVerifiers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.DEFAULT_CREDENTIAL_ID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseVerifiers({VerifierVariant.DEFAULT, VerifierVariant.REJECT_SUSPENDED})
@DisableIfImageTag(
        verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
        reason = "Credential status propagation and configurable suspended-credential rejection are unavailable"
)
class VerifierCredentialStatusPropagationE2ETest extends BaseTest {

    @BeforeEach
    void useDefaultVerifier() {
        useVerifier(verifier(VerifierVariant.DEFAULT));
    }

    @AfterEach
    void restoreDefaultVerifier() {
        useVerifier(verifier(VerifierVariant.DEFAULT));
    }

    @ParameterizedTest(name = "suspended credential with redirect_uri={0}")
    @ValueSource(booleans = {false, true})
    @XrayTest(
            key = "EIDOMNI-1302",
            summary = "A suspended credential remains usable with optional redirect and exposes status 2",
            description = """
                    Given a suspended credential, reject_suspended_credentials disabled and a verification request
                    either without or with a redirect_uri.
                    When the wallet submits that credential in an OID4VP response.
                    Then the Wallet API returns HTTP 200 with an application/json object, containing redirect_uri only
                    when requested, and management returns HTTP 200 with the credential data and SUSPENDED status 2.
                    """
    )
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.EDGE_CASE)
    void suspendedCredential_withDefaultConfiguration_thenSucceedsAndPropagatesStatusEvaluation(
            final boolean withRedirectUri
    ) {
        // Given
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final Map<String, Object> expectedDisclosedClaims =
                CredentialSubjectFixtures.mandatoryClaimsEmployeeProfile();
        final String[] undisclosedBusinessClaims = subjectClaims.keySet()
                .stream()
                .filter(claim -> !expectedDisclosedClaims.containsKey(claim))
                .toArray(String[]::new);
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                subjectClaims
        );
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.SUSPENDED);

        final String sessionNonce = UUID.randomUUID().toString();
        final URI requestedRedirectUri = UriComponentsBuilder
                .fromUriString("https://business-verifier.example/callback")
                .queryParam("session_nonce", sessionNonce)
                .build()
                .toUri();
        final VerifierManager.VerificationRequestBuilder verificationRequest = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL();
        if (withRedirectUri) {
            verificationRequest.redirectUri(requestedRedirectUri);
        }
        final ManagementResponse verification = verificationRequest.createManagementResponse();
        final RequestObject requestObject = wallet.getVerificationRequestObject(
                verification.getVerificationDeeplink()
        );
        final String presentation = batchEntry.createSelectiveDisclosurePresentationForSdJwtIndex(
                0,
                requestObject
        );

        assertThat(requestObject.getDcqlQuery().getCredentials())
                .singleElement()
                .extracting(credential -> credential.getId())
                .isEqualTo(DEFAULT_CREDENTIAL_ID);

        // When
        final ResponseEntity<String> walletResponse = wallet.respondToVerificationWithVpTokens(
                requestObject,
                List.of(presentation)
        );

        // Then
        assertThat(walletResponse.getStatusCode().value())
                .isEqualTo(200);
        assertThat(walletResponse.getHeaders().getContentType())
                .isNotNull()
                .matches(MediaType.APPLICATION_JSON::isCompatibleWith);
        assertThat(walletResponse.getBody())
                .isNotBlank();
        final JsonObject walletResponseBody = JsonParser.parseString(walletResponse.getBody()).getAsJsonObject();

        final ResponseEntity<ManagementResponse> businessVerifierResponse;
        if (withRedirectUri) {
            assertThat(walletResponseBody.has("redirect_uri"))
                    .isTrue();
            final URI holderRedirectUri = URI.create(walletResponseBody.get("redirect_uri").getAsString());
            assertThat(holderRedirectUri.isAbsolute())
                    .isTrue();
            assertThat(holderRedirectUri.getScheme())
                    .isEqualTo(requestedRedirectUri.getScheme());
            assertThat(holderRedirectUri.getAuthority())
                    .isEqualTo(requestedRedirectUri.getAuthority());
            assertThat(holderRedirectUri.getPath())
                    .isEqualTo(requestedRedirectUri.getPath());
            assertThat(UriComponentsBuilder.fromUri(holderRedirectUri)
                    .build()
                    .getQueryParams()
                    .getFirst("session_nonce"))
                    .isEqualTo(sessionNonce);
            final String responseCodeValue = UriComponentsBuilder.fromUri(holderRedirectUri)
                    .build()
                    .getQueryParams()
                    .getFirst("response_code");
            assertThat(responseCodeValue)
                    .isNotBlank();
            final UUID responseCode = UUID.fromString(responseCodeValue);
            assertThat(responseCode.version())
                    .isEqualTo(4);
            businessVerifierResponse = verifierManager.getVerificationByIdWithHttpInfo(
                    verification.getId(),
                    responseCode
            );
        } else {
            assertThat(walletResponseBody.has("redirect_uri"))
                    .isFalse();
            businessVerifierResponse = verifierManager.getVerificationByIdWithHttpInfo(verification.getId());
        }

        assertThat(businessVerifierResponse.getStatusCode().value())
                .as("Business Verifier management HTTP status")
                .isEqualTo(200);
        final ManagementResponse result = businessVerifierResponse.getBody();
        assertThat(result)
                .isNotNull();
        assertThat(result.getWalletResponse())
                .isNotNull();
        assertThat(result.getWalletResponse().getErrorCode())
                .isNull();
        assertThat(result.getWalletResponse().getErrorDescription())
                .isNull();
        assertThat(result.getWalletResponse().getCredentialSubjectData())
                .containsOnlyKeys(DEFAULT_CREDENTIAL_ID);
        @SuppressWarnings("unchecked")
        final List<Map<String, Object>> credentialData = (List<Map<String, Object>>) result
                .getWalletResponse()
                .getCredentialSubjectData()
                .get(DEFAULT_CREDENTIAL_ID);
        assertThat(credentialData)
                .singleElement()
                .satisfies(actualCredentialData -> {
                    assertThat(actualCredentialData).containsAllEntriesOf(expectedDisclosedClaims);
                    assertThat(actualCredentialData).doesNotContainKeys(undisclosedBusinessClaims);
                });
        assertThat(result.getCredentialEvaluation())
                .containsOnlyKeys(DEFAULT_CREDENTIAL_ID);
        final List<CredentialEvaluation> evaluations = result.getCredentialEvaluation().get(DEFAULT_CREDENTIAL_ID);
        assertThat(evaluations)
                .singleElement();
        final CredentialEvaluation evaluation = evaluations.getFirst();
        assertThat(evaluation.getCredentialStatus())
                .isNotNull()
                .satisfies(status -> {
                    assertThat(status.getValid()).isFalse();
                    assertThat(status.getStatus()).isEqualTo(2);
                });
        assertThat(evaluation.getValid())
                .as("A suspended credential must retain its invalid evaluation")
                .isFalse();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1303",
            summary = "A suspended credential gets Wallet HTTP 200 and management HTTP 400 when rejection is enabled",
            description = """
                    Given a suspended credential and reject_suspended_credentials enabled.
                    When the wallet submits that credential in an OID4VP response.
                    Then the Wallet API returns HTTP 200 with an application/json object without redirect_uri, while
                    the Business Verifier management API returns HTTP 400.
                    """
    )
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.EDGE_CASE)
    @Disabled("Depends on EIDOMNI-1310")
    void suspendedCredential_withRejectionEnabled_thenBusinessManagementRejects() {
        // Given
        useVerifier(verifier(VerifierVariant.REJECT_SUSPENDED));
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                subjectClaims
        );
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.SUSPENDED);

        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL()
                .createManagementResponse();
        final RequestObject requestObject = wallet.getVerificationRequestObject(
                verification.getVerificationDeeplink()
        );
        final String presentation = batchEntry.createSelectiveDisclosurePresentationForSdJwtIndex(
                0,
                requestObject
        );

        assertThat(requestObject.getDcqlQuery().getCredentials())
                .singleElement()
                .extracting(credential -> credential.getId())
                .isEqualTo(DEFAULT_CREDENTIAL_ID);

        // When
        final ResponseEntity<String> walletResponse = wallet.respondToVerificationWithVpTokens(
                requestObject,
                List.of(presentation)
        );

        // Then
        assertThat(walletResponse.getStatusCode().value())
                .isEqualTo(200);
        assertThat(walletResponse.getHeaders().getContentType())
                .isNotNull()
                .matches(MediaType.APPLICATION_JSON::isCompatibleWith);
        assertThat(walletResponse.getBody())
                .isNotBlank();
        assertThat(JsonParser.parseString(walletResponse.getBody()).getAsJsonObject().has("redirect_uri"))
                .isFalse();
        final HttpClientErrorException managementError = assertThrows(
                HttpClientErrorException.class,
                () -> verifierManager.getVerificationByIdWithHttpInfo(verification.getId())
        );
        assertThat(managementError.getStatusCode().value())
                .as("Business Verifier management HTTP status")
                .isEqualTo(400);
    }

    @ParameterizedTest(name = "revoked credential is accepted by the Wallet and rejected for business use by {0}")
    @EnumSource(value = VerifierVariant.class, names = {"DEFAULT", "REJECT_SUSPENDED"})
    @XrayTest(
            key = "EIDOMNI-1304",
            summary = "A revoked credential gets Wallet HTTP 200 and management HTTP 400",
            description = """
                    Given a revoked credential under either supported verifier status-policy configuration.
                    When the wallet submits that credential in an OID4VP response.
                    Then the Wallet API returns HTTP 200 with an application/json object without redirect_uri, while
                    the Business Verifier management API returns HTTP 400 independently of the suspended policy.
                    """
    )
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.EDGE_CASE)

    void revokedCredential_withEitherConfiguration_thenBusinessManagementRejects(
            final VerifierVariant verifierVariant
    ) {
        // Given
        useVerifier(verifier(verifierVariant));
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                subjectClaims
        );
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.REVOKED);

        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL()
                .createManagementResponse();
        final RequestObject requestObject = wallet.getVerificationRequestObject(
                verification.getVerificationDeeplink()
        );
        final String presentation = batchEntry.createSelectiveDisclosurePresentationForSdJwtIndex(
                0,
                requestObject
        );

        assertThat(requestObject.getDcqlQuery().getCredentials())
                .singleElement()
                .extracting(credential -> credential.getId())
                .isEqualTo(DEFAULT_CREDENTIAL_ID);

        // When
        final ResponseEntity<String> walletResponse = wallet.respondToVerificationWithVpTokens(
                requestObject,
                List.of(presentation)
        );

        // Then
        assertThat(walletResponse.getStatusCode().value())
                .isEqualTo(200);
        assertThat(walletResponse.getHeaders().getContentType())
                .isNotNull()
                .matches(MediaType.APPLICATION_JSON::isCompatibleWith);
        assertThat(walletResponse.getBody())
                .isNotBlank();
        assertThat(JsonParser.parseString(walletResponse.getBody()).getAsJsonObject().has("redirect_uri"))
                .isFalse();
        final HttpClientErrorException managementError = assertThrows(
                HttpClientErrorException.class,
                () -> verifierManager.getVerificationByIdWithHttpInfo(verification.getId())
        );
        assertThat(managementError.getStatusCode().value())
                .as("Business Verifier management HTTP status")
                .isEqualTo(400);
    }
}
