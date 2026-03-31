package ch.admin.bj.swiyu.swiyu_test_wallet.flows;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.issuer.model.WebhookCallback;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.webhook_callback.WebhookCallbackAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.util.List;
import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@Slf4j
public class RevocationFlowTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-711",
            summary = "Revoked credentials cannot be used in OID4VP verification flow",
            description = """
                        This test validates that once credentials have been issued and subsequently revoked by the Issuer,
                        any attempt by the Wallet to use them in an OID4VP verification flow is rejected.

                        The Issuer first issues a batch of credentials to the Wallet. After confirming successful issuance,
                        the Issuer changes the credential status to REVOKED.

                        When the Wallet attempts to present each credential to the Verifier, the verification process
                        must fail with a credential_revoked error. The Verifier must transition the verification state
                        to FAILED, ensuring that revoked credentials cannot be reused.
                    """)
    @Tag("ucv_c3")
    @Tag("ucv_o2c")
    @Tag("edge_case")
    void revokedCredential_whenVerified_thenVerificationIsRejected() {
        // Given
        final UpdateCredentialStatusRequestType updateStatus = UpdateCredentialStatusRequestType.REVOKED;

        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When - Issue credential
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId,
                subjectClaims);
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        // Then - Verify credential was issued with correct claims
        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);

        // When - Revoke the credential
        issuerManager.updateState(offer.getManagementId(), updateStatus);

        // Then - The verification failed as the credential is revoked
        for (int i = 0; i < CredentialConfigurationFixtures.BATCH_SIZE; i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(true)
                    .createManagementResponse();
            final RequestObject verificationDetails = wallet
                    .getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
            verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

            final String presentation = batchEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
                wallet.respondToVerification(SwiyuApiVersionConfig.V1, verificationDetails, presentation);
            });

            ApiErrorAssert.assertThat(ex)
                    .hasError("invalid_transaction_data")
                    .hasErrorDescription("Credential has been Revoked!")
                    .hasDetail("credential_revoked")
                    .hasErrorCode("credential_revoked");

            verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-712",
            summary = "Suspended credentials are rejected during OID4VP verification and become verifiable again once reactivated by the issuer",
            description = """
                This test validates the credential lifecycle behavior in an OID4VP verification flow when the Issuer suspends
                and later reactivates a batch of issued credentials.

                The Issuer first issues a batch of credentials to the Wallet. The Issuer then suspends the batch, and any attempt
                by the Wallet to present one of these credentials to the Verifier must be rejected with a credential_suspended error.
                Finally, the Issuer reactivates the batch by setting the status back to ISSUED, after which the Wallet can present
                the credentials successfully and the Verifier accepts the verification.
                """)
    @Tag("ucv_c3")
    @Tag("ucv_o2c")
    @Tag("edge_case")
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "Feature not available yet on stable"
    )
    void suspendedCredential_whenSuspended_thenVerificationRejected_whenRevalidated_thenVerificationAccepted() {
        // Given
        final UpdateCredentialStatusRequestType updateStatus = UpdateCredentialStatusRequestType.SUSPENDED;

        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT;

        // When - Issue credential
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId,
                subjectClaims);
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        // Then - Verify credential was issued with correct claims
        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);

        // When - Suspend the credential
        issuerManager.updateState(offer.getManagementId(), updateStatus);

        // Then - The verification fails as the credential is suspended
        for (int i = 0; i < CredentialConfigurationFixtures.BATCH_SIZE; i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(false)
                    .createManagementResponse();
            final RequestObject verificationDetails = wallet
                    .getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
            verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

            final int index = i;
            final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
                wallet.respondToVerification(SwiyuApiVersionConfig.V1, verificationDetails, batchEntry.getVerifiableCredential(index));
            });

            ApiErrorAssert.assertThat(ex)
                    .hasError("invalid_transaction_data")
                    .hasErrorDescription("Credential has been Suspended!")
                    .hasDetail("credential_suspended")
                    .hasErrorCode("credential_suspended");

            verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
        }

        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.ISSUED);

        // Then - The verification process succeed as the credential is valid again
        for (int i = 0; i < CredentialConfigurationFixtures.BATCH_SIZE; i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(false)
                    .createManagementResponse();
            final RequestObject verificationDetails = wallet
                    .getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
            verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

            wallet.respondToVerification(SwiyuApiVersionConfig.V1, verificationDetails,
                    batchEntry.getVerifiableCredential(i));

            verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-826",
            summary = "During revokation, error event callback should be trigger if the status list throw an error",
            description = """
                    This test validates that when a status list update fails during revocation, the issuer correctly 
                    handles the error without completing the revocation process. It ensures that the expected error 
                    response is returned and that a specific error webhook callback is sent instead of a successful 
                    revocation callback. Finally, it verifies that the credential remains valid and can still be 
                    successfully verified.
                    """)
    @Tag(ReportingTags.UCI_C1A)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This fix is not available on other image tags"
    )
    void errorEventCallback_whenRevokeStatusListFailed_thenVCRemainsValidAndErrorCallbackSent() {
        // Given
        cleanIssuerCallbacks();
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId, subjectClaims);
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        // Then
        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);

        // Given
        mockServerClientConfig.enableStatusListError();

        // When
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
            issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.REVOKED);
        });

        // Then - Update should contains error
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .containsDetail("Transition failed for GenericMessage")
                .containsDetail("payload=REVOKE");

        // Then - Callbacks should contains status list failed
        awaitStableIssuerCallbacks();
        WebhookCallbackAssert.assertThat(issuerCallbacks())
                .hasSizeEventually(4)
                .hasLastCallbacksInOrder(List.of(
                        new WebhookCallback()
                                .subjectId(offer.getOfferId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.IN_PROGRESS.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_OFFER),
                        new WebhookCallback()
                                .subjectId(offer.getOfferId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.ISSUED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_OFFER),
                        new WebhookCallback()
                                .subjectId(offer.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.ISSUED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_MANAGEMENT),
                        new WebhookCallback()
                                .subjectId(offer.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.ISSUANCE_ERROR)
                                .event("STATUS_LIST_UPDATE_FAILED")
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_MANAGEMENT)
                ));

        // Then - VC should still be valid
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(false)
                .createManagementResponse();
        final RequestObject verificationDetails = wallet
                .getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

        wallet.respondToVerification(SwiyuApiVersionConfig.V1, verificationDetails,
                batchEntry.getVerifiableCredential(0));

        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
    }
}
