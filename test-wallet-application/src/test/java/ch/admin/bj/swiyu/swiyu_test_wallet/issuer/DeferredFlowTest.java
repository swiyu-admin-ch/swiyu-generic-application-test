package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.issuer.model.WebhookCallback;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_offer_status_type.CredentialOfferStatusType;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_response.CredentialResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_response.CredentialResponseAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.webhook_callback.WebhookCallbackAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class DeferredFlowTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-667",
            summary = "Deferred credential issuance respects specification with 202 pending status in V1 API",
            description = """
                    This test validates that deferred credential requests conform to the specification in V1 API mode.
                    The wallet receives a 202 status and transaction ID when requesting a deferred credential, maintaining the 202 status until the issuer marks the credential as ready.
                    Once the issuer transitions the credential state to READY, the wallet can successfully retrieve the issued credential batch.
                    This ensures specification-compliant deferred issuance flow behavior.
                    """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC},
            reason = "The images have not the fix yet (The transaction_id MUST remain the same.)."
    )
    void deferredCredentialRequestV1_whenCredentialNotReady_remainsDeferred() throws InterruptedException {
        // Given
        final SwiyuApiVersionConfig apiVersion = SwiyuApiVersionConfig.V1;
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.mandatoryClaimsEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createDeferredCredentialOffer(
                supportedMetadataId,
                subjectClaims);
        final WalletBatchEntry batchEntry = (WalletBatchEntry) wallet.collectTransactionIdFromDeferredOffer(apiVersion, toUri(offer.getOfferDeeplink()));
        // Then
        assertThat(batchEntry.getTransactionId()).isNotNull();
        CredentialResponseAssert.assertThat(batchEntry.getCredentialResponse()).hasCode(202);
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.DEFERRED);

        // When
        final UUID expectedTransactionId = batchEntry.getTransactionId();
        final CredentialResponse credentialResponse = wallet.getCredentialFromTransactionId(apiVersion, batchEntry);

        // Then
        CredentialResponseAssert.assertThat(credentialResponse)
                .hasTransactionId(expectedTransactionId)
                .hasInterval()
                .hasCode(202);

        // When
        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.READY);
        wallet.getCredentialFromTransactionId(apiVersion, batchEntry);

        // Then
        CredentialResponseAssert.assertThat(credentialResponse)
                .hasTransactionId(expectedTransactionId)
                .hasInterval()
                .hasCode(202);

        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-668",
            summary = "Deferred credential issuance returns immediate error for backward compatibility in deprecated ID2 API",
            description = """
                    This test validates the non-specification-compliant behavior of the ID2 API mode for backward compatibility purposes.
                    The wallet receives a 400 error with ISSUANCE_PENDING status when requesting a deferred credential, rather than the 202 accepted response.
                    This deprecated behavior prioritizes backward compatibility with legacy systems over specification compliance.
                    The test confirms this legacy behavior is maintained during the deprecation period.
                    """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    @Deprecated(forRemoval = true)
    void deferredCredentialRequestID2_whenCredentialNotReady_remainsDeferred() {
        // Given
        final SwiyuApiVersionConfig apiVersion = SwiyuApiVersionConfig.ID2;
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.mandatoryClaimsEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createDeferredCredentialOffer(
                supportedMetadataId,
                subjectClaims);
        final WalletEntry entry = wallet.collectTransactionIdFromDeferredOffer(apiVersion, toUri(offer.getOfferDeeplink()));
        // Then
        assertThat(entry.getTransactionId()).isNotNull();
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.DEFERRED);

        // When
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class,
                () -> wallet.getCredentialFromTransactionId(apiVersion, entry));

        // Then
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasError("ISSUANCE_PENDING")
                .hasErrorDescription("The credential is not marked as ready to be issued");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-765",
            summary = "Cancelled deferred offer blocks issuance and cannot return to READY",
            description = """
                This test validates that after the issuer cancels a deferred credential offer,
                the wallet cannot request issuance using the transaction ID.
                It also confirms the issuer cannot transition the offer back to READY.
                """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    @Deprecated(forRemoval = true)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC},
            reason = "This fix is not available yet."
    )
    void deferredOfferCancelled_shouldRejectWalletCredentialRequest_andRejectReadyTransition() {
        cleanIssuerCallbacks();

        // Given
        final SwiyuApiVersionConfig apiVersion = SwiyuApiVersionConfig.ID2;
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.mandatoryClaimsEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createDeferredCredentialOffer(
                supportedMetadataId,
                subjectClaims);
        final WalletEntry entry = wallet.collectTransactionIdFromDeferredOffer(apiVersion, toUri(offer.getOfferDeeplink()));
        // Then
        assertThat(entry.getTransactionId()).isNotNull();

        // When
        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.CANCELLED);

        // Then
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.CANCELLED);

        // When
        HttpClientErrorException ex = assertThrows(HttpClientErrorException.class,
                () -> wallet.getCredentialFromTransactionId(apiVersion, entry));

        // Then
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasError("CREDENTIAL_REQUEST_DENIED")
                .hasErrorDescription("The credential cannot be issued anymore, the offer was either cancelled or expired");

        // Given
        final UpdateCredentialStatusRequestType newStatus = UpdateCredentialStatusRequestType.READY;

        // When
        ex = assertThrows(HttpClientErrorException.class,
                () -> issuerManager.updateState(offer.getManagementId(), newStatus));

        // Then
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasErrorDescription("Bad Request")
                .containsDetail("Transition failed for GenericMessage")
                .containsDetail(String.format("payload=%s", newStatus.getValue()))
                .containsDetail("oldStatus=Cancelled")
                .containsDetail(String.format("credentialId=%s", offer.getOfferId()));

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
                                .event(CredentialStatusType.DEFERRED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_OFFER),
                        new WebhookCallback()
                                .subjectId(offer.getOfferId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_DEFERRED)
                                .event(CredentialOfferStatusType.DEFERRED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_OFFER),
                        new WebhookCallback()
                                .subjectId(offer.getOfferId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.CANCELLED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_OFFER)
                ));
    }
}
