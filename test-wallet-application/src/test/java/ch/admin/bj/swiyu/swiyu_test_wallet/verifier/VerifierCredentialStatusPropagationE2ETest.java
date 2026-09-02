package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseVerifiers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;

import java.util.List;
import java.util.Map;

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

    @Test
    @XrayTest(
            key = "EIDOMNI-1302",
            summary = "A suspended credential remains usable and exposes its invalid status by default",
            description = """
                    Given a suspended credential and the verifier's default status policy.
                    When the wallet submits that credential in an OID4VP response.
                    Then verification succeeds and management exposes status 2 as an invalid credential evaluation.
                    """
    )
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.EDGE_CASE)
    void suspendedCredential_withDefaultConfiguration_thenSucceedsAndPropagatesStatusEvaluation() {
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
        final ManagementResponse result = verifierManager.verifyState(
                verification.getId(),
                VerificationStatus.SUCCESS
        );

        // Then
        assertThat(walletResponse.getStatusCode().value())
                .isEqualTo(200);
        assertThat(result.getWalletResponse())
                .isNotNull();
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
        assertThat(result.getWalletResponse().getVpToken())
                .as("Standard verification must not expose the full presentation")
                .isNullOrEmpty();
        assertThat(result.getCredentialEvaluation())
                .containsOnlyKeys(DEFAULT_CREDENTIAL_ID);
        assertThat(result.getCredentialEvaluation().get(DEFAULT_CREDENTIAL_ID))
                .singleElement()
                .satisfies(evaluation -> {
                    assertThat(evaluation.getValid())
                            .as("The suspended credential evaluation must be invalid")
                            .isFalse();
                    assertThat(evaluation.getCredentialStatus())
                            .isNotNull()
                            .satisfies(status -> {
                                assertThat(status.getValid()).isFalse();
                                assertThat(status.getStatus()).isEqualTo(2);
                            });
                });
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1303",
            summary = "A suspended credential is rejected when the verifier rejection policy is enabled",
            description = """
                    Given a suspended credential and APPLICATION_REJECTSUSPENDEDCREDENTIALS enabled.
                    When the wallet submits that credential in an OID4VP response.
                    Then submission returns credential_suspended and management contains no credential or VP data.
                    """
    )
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.EDGE_CASE)
    void suspendedCredential_withRejectionEnabled_thenFailsWithoutCredentialData() {
        // Given
        useVerifier(verifier(VerifierVariant.REJECT_SUSPENDED));
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                CredentialSubjectFixtures.completeEmployeeProfile()
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
        final HttpClientErrorException submissionError = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.respondToVerificationWithVpTokens(requestObject, List.of(presentation))
        );
        final ManagementResponse result = verifierManager.verifyState(
                verification.getId(),
                VerificationStatus.FAILED
        );

        // Then
        ApiErrorAssert.assertThat(submissionError)
                .hasStatus(400)
                .hasError("invalid_transaction_data")
                .hasDetail("credential_suspended")
                .hasErrorCode("credential_suspended");
        assertThat(result.getWalletResponse())
                .isNotNull();
        assertThat(result.getWalletResponse().getCredentialSubjectData())
                .isNullOrEmpty();
        assertThat(result.getWalletResponse().getVpToken())
                .isNullOrEmpty();
    }

    @ParameterizedTest(name = "revoked credential is rejected by {0} verifier")
    @EnumSource(value = VerifierVariant.class, names = {"DEFAULT", "REJECT_SUSPENDED"})
    @XrayTest(
            key = "EIDOMNI-1304",
            summary = "A revoked credential is rejected independently of the suspended-credential policy",
            description = """
                    Given a revoked credential under either supported verifier status-policy configuration.
                    When the wallet submits that credential in an OID4VP response.
                    Then submission returns credential_revoked and management contains no credential or VP data.
                    """
    )
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.EDGE_CASE)
    void revokedCredential_withEitherConfiguration_thenFailsWithoutCredentialData(
            final VerifierVariant verifierVariant
    ) {
        // Given
        useVerifier(verifier(verifierVariant));
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                CredentialSubjectFixtures.completeEmployeeProfile()
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
        final HttpClientErrorException submissionError = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.respondToVerificationWithVpTokens(requestObject, List.of(presentation))
        );
        final ManagementResponse result = verifierManager.verifyState(
                verification.getId(),
                VerificationStatus.FAILED
        );

        // Then
        ApiErrorAssert.assertThat(submissionError)
                .hasStatus(400)
                .hasError("invalid_transaction_data")
                .hasDetail("credential_revoked")
                .hasErrorCode("credential_revoked");
        assertThat(result.getWalletResponse())
                .isNotNull();
        assertThat(result.getWalletResponse().getCredentialSubjectData())
                .isNullOrEmpty();
        assertThat(result.getWalletResponse().getVpToken())
                .isNullOrEmpty();
    }
}
