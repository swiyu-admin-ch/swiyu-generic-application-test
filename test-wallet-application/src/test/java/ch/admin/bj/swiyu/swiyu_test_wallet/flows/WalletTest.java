package ch.admin.bj.swiyu.swiyu_test_wallet.flows;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact.SdJwtCredential;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class WalletTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-393",
            summary = "Successful issuance and verification of a bound SD-JWT credential with selective disclosure",
            description = """
                    This test validates the immediate issuance of a bound SD-JWT credential that requires selective
                    disclosure during verification. The wallet constructs a derived presentation based on the verifier's
                    requirements and the credential is successfully validated.
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    @Tag(ReportingTags.UCI_I1_ISSUING_VERIFIABLE_CREDENTIALS)
    @Tag(ReportingTags.UCI_I1A_CREATE_VERIFIABLE_CREDENTIALS)
    @Tag(ReportingTags.UCV_O2_SUBMIT_VERIFICATION_PRESENTATION)
    @Tag(ReportingTags.UCV_O2A_VERIFY_PRESENTATION_SUBMISSION_AND_SD_JWT_CREDENTIAL)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void boundNonDeferredCredential_whenIssuedAndVerifiedWithDcql_thenSuccess() {
        // Given
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId,
                subjectClaims);
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        // Then
        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);

        // When
        for (int i = 0; i < batchEntry.getIssuedCredentials().size(); i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL()
                    .createManagementResponse();
            final RequestObject verificationDetails = wallet
                    .getVerificationRequestObject(verification.getVerificationDeeplink());
            verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
            final String presentation = batchEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            wallet.respondToVerification(verificationDetails, presentation);
            // Then
            verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-390",
            summary = "Successful deferred issuance and verification of a bound SD-JWT credential",
            description = """
                    This test validates the end-to-end deferred issuance flow for a bound SD-JWT credential
                    with selective disclosure requirements. The wallet retrieves the credential using a transaction ID
                    and successfully constructs a presentation that satisfies the verifier's requirements.
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    @Tag(ReportingTags.UCI_I1_ISSUING_VERIFIABLE_CREDENTIALS)
    @Tag(ReportingTags.UCI_I1B_CREATE_DEFERRED_VERIFIABLE_CREDENTIALS)
    @Tag(ReportingTags.UCV_O2_SUBMIT_VERIFICATION_PRESENTATION)
    @Tag(ReportingTags.UCV_O2A_VERIFY_PRESENTATION_SUBMISSION_AND_SD_JWT_CREDENTIAL)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This feature is not available yet"
    )
    void boundDeferredCredential_whenIssuedAndVerifiedWithDcql_thenSuccess() {
        // Given
        final Map<String, Object> initialSubjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final Map<String, Object> updatedSubjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        updatedSubjectClaims.put(CredentialSubjectFixtures.NUMBER_MANDATORY_CLAIM_KEY, 15.0);
        updatedSubjectClaims.remove(CredentialSubjectFixtures.NUMBER_OPTIONAL_CLAIM_KEY);
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createDeferredCredentialOffer(supportedMetadataId,
                initialSubjectClaims);
        final WalletBatchEntry batchEntry = wallet.collectTransactionIdFromDeferredOffer(toUri(offer.getOfferDeeplink()));
        // Then
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.DEFERRED);

        // When
        issuerManager.updateCredentialForDeferredFlowRequestCreation(offer.getManagementId(), updatedSubjectClaims);
        // Then
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.READY);

        // When
        wallet.getCredentialFromTransactionId(batchEntry);
        // Then
        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(updatedSubjectClaims);

        // When
        for (int i = 0; i < batchEntry.getIssuedCredentials().size(); i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(false)
                    .createManagementResponse();
            final RequestObject verificationDetails = wallet
                    .getVerificationRequestObject(verification.getVerificationDeeplink());
            verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
            final String presentation = batchEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            wallet.respondToVerification(verificationDetails, presentation);
            // Then
            verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-561",
            summary = "Verification rejection of an unbound credential when holder binding proof is required",
            description = """
                    This test validates that a DCQL-based verification request requiring holder binding is correctly rejected
                    when the wallet attempts to present an unbound credential. The verifier detects the missing holder key binding
                    proof and rejects the presentation with an appropriate error.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCV_O2_SUBMIT_VERIFICATION_PRESENTATION)
    @Tag(ReportingTags.UCV_O2A_VERIFY_PRESENTATION_SUBMISSION_AND_SD_JWT_CREDENTIAL)
    @DisableIfImageTag(
            verifier = {ImageTags.RC},
            reason = "This is fixed in next versions"
    )
    void verifyDCQLRequestHolderBindingWalletWithoutHolder_thenReject() {
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);

        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        assertThat(batchEntry.getCredentialOffer()).isNotNull();

        var deepLink = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL()
                .create();

        final RequestObject verificationDetails = wallet.getVerificationRequestObject(deepLink);
        // A malicious issuer removes only the holder binding; the signature and disclosures remain valid.
        final String res = SdJwtCredential.parse(batchEntry.getVerifiableCredential(0))
                .resign()
                .signedWith(issuerConfig.getKeyPair())
                .withoutHolderBinding()
                .build()
                .serialize();

        assertThat(verificationDetails.getDcqlQuery())
                .isNotNull();

        assertThrows(HttpClientErrorException.class, () -> {
            wallet.respondToVerification(verificationDetails, res);
        });
    }
}
