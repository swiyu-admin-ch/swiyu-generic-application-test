package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationErrorResponseCode;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockAttestationAuthority;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerHandle;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.SwiyuEnvironmentRegistry;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierHandle;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import({CompleteEnvironmentTestConfiguration.class, RegressionEnvironmentTestConfiguration.class})
@Tag(ReportingTags.VERSION_REGRESSION)
class VerifierVerificationVersionRegressionTest {

    private static final String WALLET_REJECTION = "access_denied";
    private static final String WALLET_REJECTION_DESCRIPTION = "Holder declined the verification request";

    @Autowired
    private RegressionEnvironmentFactory regressionEnvironment;

    @Autowired
    private SwiyuEnvironmentRegistry environmentRegistry;

    @Autowired
    private MockAttestationAuthority mockAttestationAuthority;

    @Test
    @XrayTest(
            key = "EIDOMNI-1284",
            summary = "Verifier request lifecycle remains compatible from Previous to Candidate",
            description = """
                    Prepares pending, successful and failed verification states on the Previous Verifier. Once every
                    historical request is persisted, the test starts the Candidate Verifier only once on the same
                    schema. Candidate completes the pending requests and preserves the terminal states without allowing
                    an old wallet response to reopen them.
                    """)
    void verificationsPreparedByPrevious_whenVerifierUpgradesOnce_thenCandidateCompletesLifecycleMatrix() {
        final IssuerHandle issuer = environmentRegistry.issuer(IssuerVariant.DEFAULT);

        try (final VerifierVersionTransition transition = regressionEnvironment.verifierTransition()) {
            final VerifierHandle previousVerifier = transition.startPrevious();
            final String expectedVerifierDid = previousVerifier.config().getVerifierDid();
            final String expectedDatabaseSchema = previousVerifier.imageConfig().getDbSchema();
            final Map<String, Object> expectedDisclosures = CredentialSubjectFixtures.completeEmployeeProfile();
            final Wallet wallet = new Wallet(
                    RestClient.builder().build(),
                    issuer.serviceLocation(),
                    previousVerifier.serviceLocation()
            );
            wallet.setUseDPoP(issuer.imageConfig().isEnforceDpop());
            wallet.setUseEncryption(issuer.imageConfig().isEncryptionEnforce());
            wallet.setSignedMetadataPreferred(issuer.imageConfig().isSignedMetadata());
            wallet.setMockAttestationAuthority(mockAttestationAuthority);

            final CredentialWithDeeplinkResponse offer = issuer.manager().createCredentialOffer(
                    CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                    expectedDisclosures
            );
            final WalletBatchEntry walletBatch = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
            SdJwtBatchAssert.assertThat(walletBatch.getIssuedCredentials())
                    .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                    .areUnique()
                    .allHaveExactlyInAnyOrderDisclosures(expectedDisclosures);
            wallet.setUseEncryption(false);

            final PreviousVerificationScenarios scenarios = transition.preparePrevious(verifier -> {
                // Started by Previous for completion by Candidate.
                final ManagementResponse startedForCandidateSuccess = verifier.manager()
                        .verificationRequest()
                        .acceptedIssuerDid(issuer.config().getIssuerDid())
                        .withUniversityDCQL(true)
                        .createManagementResponse();
                assertThat(startedForCandidateSuccess.getState())
                        .as("Verification started by Previous for Candidate completion")
                        .isEqualTo(VerificationStatus.PENDING);

                final RequestObject candidateSuccessRequest = wallet.getVerificationRequestObject(
                        startedForCandidateSuccess.getVerificationDeeplink()
                );
                assertThat(candidateSuccessRequest.getState())
                        .as("State created by Previous")
                        .isNotBlank();
                assertThat(candidateSuccessRequest.getNonce())
                        .as("Nonce created by Previous")
                        .isNotBlank();
                final String candidateSuccessPresentation = walletBatch.createPresentationForSdJwtIndex(
                        0,
                        candidateSuccessRequest
                );

                // Created by Previous but not started by the wallet until Candidate is running.
                final ManagementResponse createdOnlyByPrevious = verifier.manager()
                        .verificationRequest()
                        .acceptedIssuerDid(issuer.config().getIssuerDid())
                        .withUniversityDCQL(true)
                        .createManagementResponse();
                assertThat(createdOnlyByPrevious.getState())
                        .as("Verification created but not started on Previous")
                        .isEqualTo(VerificationStatus.PENDING);

                // Started by Previous and explicitly rejected by the wallet on Candidate.
                final ManagementResponse startedForCandidateRejection = verifier.manager()
                        .verificationRequest()
                        .acceptedIssuerDid(issuer.config().getIssuerDid())
                        .withUniversityDCQL(true)
                        .createManagementResponse();
                final RequestObject candidateRejectionRequest = wallet.getVerificationRequestObject(
                        startedForCandidateRejection.getVerificationDeeplink()
                );
                assertThat(candidateRejectionRequest.getState())
                        .as("State of the request to reject on Candidate")
                        .isNotBlank();
                assertThat(candidateRejectionRequest.getNonce())
                        .as("Nonce of the request to reject on Candidate")
                        .isNotBlank();
                assertThat(verifier.manager().getVerificationById(startedForCandidateRejection.getId()).getState())
                        .as("Verification started on Previous before Candidate rejection")
                        .isEqualTo(VerificationStatus.PENDING);

                // Completed successfully on Previous; Candidate must retain the terminal state.
                final ManagementResponse successfulOnPrevious = verifier.manager()
                        .verificationRequest()
                        .acceptedIssuerDid(issuer.config().getIssuerDid())
                        .withUniversityDCQL(true)
                        .createManagementResponse();
                final RequestObject previousSuccessRequest = wallet.getVerificationRequestObject(
                        successfulOnPrevious.getVerificationDeeplink()
                );
                final String previousSuccessPresentation = walletBatch.createPresentationForSdJwtIndex(
                        0,
                        previousSuccessRequest
                );
                wallet.respondToVerification(previousSuccessRequest, previousSuccessPresentation);
                assertThat(verifier.manager().getVerificationById(successfulOnPrevious.getId()).getState())
                        .as("Verification completed successfully on Previous")
                        .isEqualTo(VerificationStatus.SUCCESS);

                // Rejected on Previous; Candidate must retain both the terminal state and its business reason.
                final ManagementResponse rejectedOnPrevious = verifier.manager()
                        .verificationRequest()
                        .acceptedIssuerDid(issuer.config().getIssuerDid())
                        .withUniversityDCQL(true)
                        .createManagementResponse();
                final RequestObject previousRejectionRequest = wallet.getVerificationRequestObject(
                        rejectedOnPrevious.getVerificationDeeplink()
                );
                final String presentationForRejectedRequest = walletBatch.createPresentationForSdJwtIndex(
                        0,
                        previousRejectionRequest
                );
                wallet.respondToVerificationWithError(
                        previousRejectionRequest,
                        WALLET_REJECTION,
                        WALLET_REJECTION_DESCRIPTION
                );
                final ManagementResponse previousFailedVerification = verifier.manager().getVerificationById(
                        rejectedOnPrevious.getId()
                );
                assertThat(previousFailedVerification.getState())
                        .as("Verification rejected on Previous")
                        .isEqualTo(VerificationStatus.FAILED);
                assertThat(previousFailedVerification.getWalletResponse())
                        .as("Wallet rejection persisted by Previous")
                        .isNotNull();
                assertThat(previousFailedVerification.getWalletResponse().getErrorCode())
                        .as("Wallet rejection code persisted by Previous")
                        .isEqualTo(VerificationErrorResponseCode.CLIENT_REJECTED);
                assertThat(previousFailedVerification.getWalletResponse().getErrorDescription())
                        .as("Wallet rejection description persisted by Previous")
                        .isEqualTo(WALLET_REJECTION_DESCRIPTION);

                return new PreviousVerificationScenarios(
                        new StartedVerification(
                                startedForCandidateSuccess.getId(),
                                candidateSuccessRequest,
                                candidateSuccessPresentation
                        ),
                        createdOnlyByPrevious,
                        new StartedVerification(
                                startedForCandidateRejection.getId(),
                                candidateRejectionRequest,
                                walletBatch.createPresentationForSdJwtIndex(0, candidateRejectionRequest)
                        ),
                        new StartedVerification(
                                successfulOnPrevious.getId(),
                                previousSuccessRequest,
                                previousSuccessPresentation
                        ),
                        new StartedVerification(
                                rejectedOnPrevious.getId(),
                                previousRejectionRequest,
                                presentationForRejectedRequest
                        )
                );
            });

            // Candidate starts only once, after all Previous verification states have been prepared.
            final VerifierHandle candidateVerifier = transition.upgradeToCandidate();
            wallet.useVerifier(candidateVerifier);
            assertThat(candidateVerifier.config().getVerifierDid())
                    .as("Candidate Verifier DID")
                    .isEqualTo(expectedVerifierDid);
            assertThat(candidateVerifier.imageConfig().getDbSchema())
                    .as("Candidate Verifier database schema")
                    .isEqualTo(expectedDatabaseSchema);

            // Candidate completes the long-lived request started by Previous.
            assertThat(candidateVerifier.manager().getVerificationById(
                            scenarios.startedForCandidateSuccess().managementId()
                    ).getState())
                    .as("Previous-started verification before Candidate response")
                    .isEqualTo(VerificationStatus.PENDING);
            wallet.respondToVerification(
                    scenarios.startedForCandidateSuccess().requestObject(),
                    scenarios.startedForCandidateSuccess().presentation()
            );
            assertThat(candidateVerifier.manager().getVerificationById(
                            scenarios.startedForCandidateSuccess().managementId()
                    ).getState())
                    .as("Previous-started verification completed by Candidate")
                    .isEqualTo(VerificationStatus.SUCCESS);

            // Candidate starts and completes the request that was only created by Previous.
            assertThat(candidateVerifier.manager().getVerificationById(
                            scenarios.createdOnlyByPrevious().getId()
                    ).getState())
                    .as("Previous-created verification before Candidate starts it")
                    .isEqualTo(VerificationStatus.PENDING);
            final RequestObject candidateOnlyRequest = wallet.getVerificationRequestObject(
                    scenarios.createdOnlyByPrevious().getVerificationDeeplink()
            );
            assertThat(candidateOnlyRequest.getState())
                    .as("State produced when Candidate starts the historical request")
                    .isNotBlank();
            assertThat(candidateOnlyRequest.getNonce())
                    .as("Nonce produced when Candidate starts the historical request")
                    .isNotBlank();
            wallet.respondToVerification(
                    candidateOnlyRequest,
                    walletBatch.createPresentationForSdJwtIndex(0, candidateOnlyRequest)
            );
            assertThat(candidateVerifier.manager().getVerificationById(
                            scenarios.createdOnlyByPrevious().getId()
                    ).getState())
                    .as("Previous-created verification completed entirely by Candidate")
                    .isEqualTo(VerificationStatus.SUCCESS);

            // Candidate records a wallet rejection for the request started by Previous.
            assertThat(candidateVerifier.manager().getVerificationById(
                            scenarios.startedForCandidateRejection().managementId()
                    ).getState())
                    .as("Previous-started verification before Candidate rejection")
                    .isEqualTo(VerificationStatus.PENDING);
            wallet.respondToVerificationWithError(
                    scenarios.startedForCandidateRejection().requestObject(),
                    WALLET_REJECTION,
                    WALLET_REJECTION_DESCRIPTION
            );
            final ManagementResponse rejectedByCandidate = candidateVerifier.manager().getVerificationById(
                    scenarios.startedForCandidateRejection().managementId()
            );
            assertThat(rejectedByCandidate.getState())
                    .as("Previous-started verification rejected on Candidate")
                    .isEqualTo(VerificationStatus.FAILED);
            assertThat(rejectedByCandidate.getWalletResponse())
                    .as("Wallet rejection persisted by Candidate")
                    .isNotNull();
            assertThat(rejectedByCandidate.getWalletResponse().getErrorCode())
                    .as("Wallet rejection code persisted by Candidate")
                    .isEqualTo(VerificationErrorResponseCode.ACCESS_DENIED);
            assertThat(rejectedByCandidate.getWalletResponse().getErrorDescription())
                    .as("Wallet rejection description persisted by Candidate")
                    .isEqualTo(WALLET_REJECTION_DESCRIPTION);

            // Candidate preserves Previous SUCCESS and rejects a replay of its old response.
            assertThat(candidateVerifier.manager().getVerificationById(
                            scenarios.successfulOnPrevious().managementId()
                    ).getState())
                    .as("Previous SUCCESS after Candidate starts")
                    .isEqualTo(VerificationStatus.SUCCESS);
            final HttpClientErrorException successfulReplay = assertThrows(
                    HttpClientErrorException.class,
                    () -> wallet.respondToVerificationWithVpTokens(
                            scenarios.successfulOnPrevious().requestObject(),
                            List.of(scenarios.successfulOnPrevious().presentation())
                    )
            );
            assertThat(successfulReplay.getStatusCode().value())
                    .as("Replay response status for a successful historical verification")
                    .isEqualTo(410);
            assertThat(candidateVerifier.manager().getVerificationById(
                            scenarios.successfulOnPrevious().managementId()
                    ).getState())
                    .as("Previous SUCCESS after replay attempt on Candidate")
                    .isEqualTo(VerificationStatus.SUCCESS);

            // Candidate preserves Previous FAILED and rejects a later valid presentation.
            final ManagementResponse failedOnCandidate = candidateVerifier.manager().getVerificationById(
                    scenarios.rejectedOnPrevious().managementId()
            );
            assertThat(failedOnCandidate.getState())
                    .as("Previous FAILED after Candidate starts")
                    .isEqualTo(VerificationStatus.FAILED);
            assertThat(failedOnCandidate.getWalletResponse())
                    .as("Previous wallet rejection after Candidate starts")
                    .isNotNull();
            assertThat(failedOnCandidate.getWalletResponse().getErrorCode())
                    .as("Previous wallet rejection code after Candidate starts")
                    .isEqualTo(VerificationErrorResponseCode.CLIENT_REJECTED);
            assertThat(failedOnCandidate.getWalletResponse().getErrorDescription())
                    .as("Previous wallet rejection description after Candidate starts")
                    .isEqualTo(WALLET_REJECTION_DESCRIPTION);
            final HttpClientErrorException failedReplay = assertThrows(
                    HttpClientErrorException.class,
                    () -> wallet.respondToVerificationWithVpTokens(
                            scenarios.rejectedOnPrevious().requestObject(),
                            List.of(scenarios.rejectedOnPrevious().presentation())
                    )
            );
            assertThat(failedReplay.getStatusCode().value())
                    .as("Late valid response status for a failed historical verification")
                    .isEqualTo(410);
            final ManagementResponse failedAfterReplay = candidateVerifier.manager().getVerificationById(
                    scenarios.rejectedOnPrevious().managementId()
            );
            assertThat(failedAfterReplay.getState())
                    .as("Previous FAILED after late valid response on Candidate")
                    .isEqualTo(VerificationStatus.FAILED);
            assertThat(failedAfterReplay.getWalletResponse())
                    .as("Previous wallet rejection retained after late valid response")
                    .isNotNull();
            assertThat(failedAfterReplay.getWalletResponse().getErrorCode())
                    .as("Previous wallet rejection code retained after late valid response")
                    .isEqualTo(VerificationErrorResponseCode.CLIENT_REJECTED);
            assertThat(failedAfterReplay.getWalletResponse().getErrorDescription())
                    .as("Previous wallet rejection description retained after late valid response")
                    .isEqualTo(WALLET_REJECTION_DESCRIPTION);
        }
    }

    private record PreviousVerificationScenarios(
            StartedVerification startedForCandidateSuccess,
            ManagementResponse createdOnlyByPrevious,
            StartedVerification startedForCandidateRejection,
            StartedVerification successfulOnPrevious,
            StartedVerification rejectedOnPrevious) {
    }

    private record StartedVerification(UUID managementId, RequestObject requestObject, String presentation) {
    }
}
