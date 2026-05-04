package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.util.List;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierManagementTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-550",
            summary = "Business verifier initiates a DCQL verification process and receives a deeplink",
            description = """
                    This test validates that a Business Verifier can successfully initiate a DCQL-based verification
                    process through the management API, persist the verification entry with DCQL query constraints,
                    and return a verification deeplink suitable for QR code generation.
                    """
    )
    @Tag(ReportingTags.UCV_M1)
    @Tag(ReportingTags.HAPPY_PATH)
    void verifierInitiatesDCQLVerification_thenManagementEntryAndDeeplinkCreated() {

        // GIVEN
        final String acceptedIssuerDid = "did:example:" + UUID.randomUUID();
        final VerifierManager.VerificationRequestBuilder verifierManagerRequest = verifierManager
                .verificationRequest()
                .acceptedIssuerDid(acceptedIssuerDid)
                .withUniversityDCQL();

        final PresentationDefinition expectedPresentationDefinition =
                verifierManagerRequest.getRequest().getPresentationDefinition();
        final DcqlQueryDto expectedDcqlQuery =
                verifierManagerRequest.getRequest().getDcqlQuery();
        final List<DcqlClaimDto> expectedClaims =
                expectedDcqlQuery.getCredentials().getFirst().getClaims();

        // WHEN
        final ManagementResponse managementResponse =
                verifierManagerRequest
                        .createManagementResponse();

        // THEN – response returned
        assertThat(managementResponse)
                .as("Management response must be returned when initiating a verification")
                .isNotNull();

        // THEN – deeplink created (UCV_M1B)
        assertThat(managementResponse.getVerificationDeeplink())
                .as("Verification deeplink must be provided to allow QR code generation")
                .isNotNull()
                .startsWith("swiyu-verify://");

        assertThat(managementResponse.getId())
                .as("Verification management entry must expose a verificationId for tracking")
                .isNotNull();

        // THEN – management entry persisted (UCV_M1A)
        final ManagementResponse persistedEntry =
                verifierManager.getVerificationById(managementResponse.getId());
        final RequestObject verificationDetails =
                wallet.getVerificationDetailsUnsigned(managementResponse.getVerificationDeeplink());
        final DcqlQueryDto persistedDcqlQuery = verificationDetails.getDcqlQuery();
        final List<DcqlClaimDto> persistedClaims =
                persistedDcqlQuery.getCredentials().getFirst().getClaims();

        assertThat(persistedEntry)
                .as("Verification management entry must be persisted and retrievable by id")
                .isNotNull();

        assertThat(persistedEntry.getState())
                .as("Newly created verification must start in PENDING state")
                .isEqualTo(VerificationStatus.PENDING);

        assertThat(persistedEntry.getId())
                .as("Persisted entry id must match the management response id")
                .isEqualTo(managementResponse.getId());

        assertThat(persistedDcqlQuery)
                .as("DCQL query must be persisted with the verification entry")
                .isNotNull();

        assertThat(persistedDcqlQuery.getCredentials())
                .as("DCQL query must contain exactly one credential query")
                .hasSize(1);

        assertThat(persistedClaims)
                .as("DCQL credential must define the same number of claims as provided")
                .hasSameSizeAs(expectedClaims);

        assertThat(
                List.of(
                        persistedClaims.get(0).getPath().getFirst(),
                        persistedClaims.get(1).getPath().getFirst(),
                        persistedClaims.get(2).getPath().getFirst()
                )
        )
                .as("DCQL credential must request the same claims as provided")
                .containsExactlyInAnyOrder(
                        expectedClaims.get(0).getPath().getFirst(),
                        expectedClaims.get(1).getPath().getFirst(),
                        expectedClaims.get(2).getPath().getFirst()
                );
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-551",
            summary = "Verifier cannot initiate a verification without a presentation definition",
            description = """
                    This test validates that the Business Verifier management API correctly rejects verification
                    request creation when no presentation definition is provided, ensuring that all verification
                    requests contain valid presentation requirements.
                    """
    )
    @Tag(ReportingTags.UCV_M1)
    @Tag(ReportingTags.EDGE_CASE)
    void verifierInitiatesVerification_withoutPresentation_thenRejected() {

        // GIVEN
        final String acceptedIssuerDid = "did:example:" + UUID.randomUUID();
        final VerifierManager.VerificationRequestBuilder verifierManagerRequest = verifierManager
                .verificationRequest(true)
                .acceptedIssuerDid(acceptedIssuerDid)
                .presentationDefinition(null);

        // WHEN
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () ->
                verifierManagerRequest.createManagementResponse()
        );

        // THEN
        assertThat(errorCode(ex))
                .as("Invalid refresh token must be rejected")
                .isEqualTo(400);
        assertThat(errorJson(ex))
                .containsEntry("error_description", "dcqlQuery: must not be null");
    }

    @XrayTest(
            key = "EIDOMNI-552",
            summary = "Business verifier retrieves verification result after successful DCQL verification",
            description = """
                    This test validates that a Business Verifier can successfully retrieve the final
                    verification result after a wallet has completed a successful DCQL presentation and verification flow.
                    """
    )
    @Tag(ReportingTags.UCV_M3)
    @Tag(ReportingTags.HAPPY_PATH)
    @Test
    void verifierRetrievesVerificationResult_afterSuccessfulVerification() {

        // GIVEN – credential issued to wallet
        final CredentialWithDeeplinkResponse response =
                issuerManager.createCredentialOffer("bound_example_sd_jwt");
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(response.getOfferDeeplink()));

        // GIVEN – verifier initiates verification
        final VerifierManager.VerificationRequestBuilder verifierManagerRequest = verifierManager
                .verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL();

        final ManagementResponse managementResponse =
                verifierManagerRequest
                        .createManagementResponse();

        // WHEN – wallet performs verification
        final RequestObject verificationDetails =
                wallet.getVerificationDetailsUnsigned(managementResponse.getVerificationDeeplink());

        final String presentation =
                batchEntry.createPresentationForSdJwtIndex(
                        0,
                        verificationDetails
                );

        wallet.respondToVerification(verificationDetails, presentation);

        // THEN – verifier retrieves verification result (UCV_M3)
        final ManagementResponse verificationResult =
                verifierManager.getVerificationById(managementResponse.getId());

        assertThat(verificationResult)
                .as("Verifier must be able to retrieve verification result after success")
                .isNotNull();

        assertThat(verificationResult.getState())
                .as("Retrieved verification result must be SUCCESS")
                .isEqualTo(VerificationStatus.SUCCESS);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-553",
            summary = "Verifier cannot retrieve a verification result for an unknown verification id",
            description = """
                    This test validates that the Business Verifier management API returns HTTP 404 when attempting
                    to retrieve verification results for a non-existent verification identifier, preventing access
                    to unauthorized or deleted verification entries.
                    """
    )
    @Tag(ReportingTags.UCV_M3)
    @Tag(ReportingTags.EDGE_CASE)
    void verifierRetrievesVerificationResult_withUnknownVerificationId_thenNotFound() {

        // GIVEN – a non-existing verification identifier
        final UUID randomId = UUID.randomUUID();

        // WHEN – verifier attempts to retrieve the verification result (UCV_M3)
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () ->
                verifierManager.getVerificationById(randomId)
        );

        // THEN – retrieval is rejected with NOT_FOUND
        assertThat(errorCode(ex))
                .as("Retrieving a verification result for an unknown id must return 404")
                .isEqualTo(404);
        assertThat(errorJson(ex))
                .containsEntry("detail", String.format("The verification with the identifier '%s' was not found", randomId.toString()));
    }
}
