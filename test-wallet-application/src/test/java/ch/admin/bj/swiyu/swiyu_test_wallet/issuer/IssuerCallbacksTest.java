package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.issuer.model.WebhookCallback;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.webhook_callback.WebhookCallbackAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@ActiveProfiles({"issuer-strict"})
public class IssuerCallbacksTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-TC-TRANS-01",
            summary = "ManagementEntity lifecycle covers T1 → T2 → T3 → T4 → T8",
            description = """
                    This test validates the ManagementEntity state machine transition coverage:
                    T1 → T2 → T3 → T4 → T8.
                    
                    Two credential offers are created to ensure state isolation between management entities.
                    
                    Covered transitions:
                    - T1: ISSUE
                    - T2: SUSPEND
                    - T3: ISSUE (from SUSPENDED)
                    - T4: REVOKE
                    - T8: REVOKE (idempotent)
                    """
    )
    public void managementEntity_fullLifecycle_shouldCover_T1_T2_T3_T4_T8() {
        wallet.setUseDPoP(true);

        cleanIssuerCallbacks();

        final CredentialWithDeeplinkResponse offer1 =
                issuerManager.createCredentialWithSignedJwt(jwtKey, keyId, CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);

        cleanIssuerCallbacks();
        WebhookCallbackAssert.assertThat(issuerCallbacks())
                .hasSizeEventually(0);

        wallet.collectOfferV1(toUri(offer1.getOfferDeeplink()));

        issuerManager.verifyStatus(offer1.getManagementId(), CredentialStatusType.ISSUED);

        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer1.getManagementId(), UpdateCredentialStatusRequestType.SUSPENDED);

        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer1.getManagementId(), UpdateCredentialStatusRequestType.ISSUED);

        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer1.getManagementId(), UpdateCredentialStatusRequestType.ISSUED);

        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer1.getManagementId(), UpdateCredentialStatusRequestType.REVOKED);

        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer1.getManagementId(), UpdateCredentialStatusRequestType.REVOKED);

        awaitStableIssuerCallbacks();
        WebhookCallbackAssert.assertThat(issuerCallbacks())
                .hasSizeEventually(6)
                .hasLastCallbacksInOrder(List.of(
                        new WebhookCallback()
                                .subjectId(offer1.getOfferId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.IN_PROGRESS.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.OFFER),
                        new WebhookCallback()
                                .subjectId(offer1.getOfferId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.ISSUED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.OFFER),
                        new WebhookCallback()
                                .subjectId(offer1.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.ISSUED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.MANAGEMENT),
                        new WebhookCallback()
                                .subjectId(offer1.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.SUSPENDED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.MANAGEMENT),
                        new WebhookCallback()
                                .subjectId(offer1.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.ISSUED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.MANAGEMENT),
                        new WebhookCallback()
                                .subjectId(offer1.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.REVOKED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.MANAGEMENT)
                ));

        final CredentialWithDeeplinkResponse offer2 =
                issuerManager.createCredentialWithSignedJwt(jwtKey, keyId, CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);

        cleanIssuerCallbacks();

        wallet.collectOfferV1(toUri(offer2.getOfferDeeplink()));

        issuerManager.verifyStatus(offer2.getManagementId(), CredentialStatusType.ISSUED);

        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer2.getManagementId(), UpdateCredentialStatusRequestType.SUSPENDED);

        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer2.getManagementId(), UpdateCredentialStatusRequestType.SUSPENDED);

        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer2.getManagementId(), UpdateCredentialStatusRequestType.REVOKED);

        awaitStableIssuerCallbacks();
        WebhookCallbackAssert.assertThat(issuerCallbacks())
                .hasSizeEventually(5)
                .hasLastCallbacksInOrder(List.of(
                        new WebhookCallback()
                                .subjectId(offer2.getOfferId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.IN_PROGRESS.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.OFFER),
                        new WebhookCallback()
                                .subjectId(offer2.getOfferId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.ISSUED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.OFFER),
                        new WebhookCallback()
                                .subjectId(offer2.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.ISSUED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.MANAGEMENT),
                        new WebhookCallback()
                                .subjectId(offer2.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.SUSPENDED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.MANAGEMENT),
                        new WebhookCallback()
                                .subjectId(offer2.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.REVOKED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.MANAGEMENT)
                ));
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-TC-TRANS-02",
            summary = "Deferred lifecycle emits callbacks for offer and management state changes",
            description = """
                    This test validates that webhook callbacks are emitted for a deferred credential offer lifecycle.
                    
                    A deferred offer is created, claimed by the wallet (transaction-based retrieval),
                    transitions into a deferred state, then is marked ready by the issuer, and finally issued
                    when the wallet retrieves the credential.
                    
                    The test verifies that callbacks are emitted in the correct order and with the correct trigger
                    (offer vs management), ensuring external observers can reliably track lifecycle state changes.
                    """
    )
    public void deferredOffer_lifecycle_shouldEmitCallbacks() {
        final SwiyuApiVersionConfig apiVersion = SwiyuApiVersionConfig.V1;
        wallet.setUseDPoP(true);

        cleanIssuerCallbacks();
        WebhookCallbackAssert.assertThat(issuerCallbacks())
                .hasSizeEventually(0);

        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.mandatoryClaimsEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // 1) Create deferred offer
        final CredentialWithDeeplinkResponse offer = issuerManager.createDeferredCredentialWithSignedJwt(
                jwtKey, keyId, supportedMetadataId
        );

        cleanIssuerCallbacks();
        WebhookCallbackAssert.assertThat(issuerCallbacks())
                .hasSizeEventually(0);

        // 2) Wallet claims → should move offer into "claiming in progress" and then "deferred"
        final WalletBatchEntry entry = (WalletBatchEntry) wallet.collectTransactionIdFromDeferredOffer(
                apiVersion,
                toUri(offer.getOfferDeeplink())
        );

        assertThat(entry.getTransactionId()).isNotNull();
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.DEFERRED);

        // At this point, we expect callbacks for:
        // - Offer lifecycle: IN_PROGRESS (trigger OFFER)
        // - Management lifecycle: DEFERRED (trigger MANAGEMENT)  (depending on implementation, can be OFFER too)
        awaitStableIssuerCallbacks();
        WebhookCallbackAssert.assertThat(issuerCallbacks())
                .hasLastCallbacksInOrder(List.of(
                        new WebhookCallback()
                                .subjectId(offer.getOfferId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event("IN_PROGRESS")
                                .eventTrigger(WebhookCallback.EventTriggerEnum.OFFER),
                        new WebhookCallback()
                                .subjectId(offer.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event("DEFERRED")
                                .eventTrigger(WebhookCallback.EventTriggerEnum.MANAGEMENT)
                ));

        // 3) Issuer marks READY (only allowed for deferred offers)
        cleanIssuerCallbacks();
        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer.getManagementId(), UpdateCredentialStatusRequestType.READY);

        awaitStableIssuerCallbacks();
        WebhookCallbackAssert.assertThat(issuerCallbacks())
                .hasLastCallbacksInOrder(List.of(
                        new WebhookCallback()
                                .subjectId(offer.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event("READY")
                                .eventTrigger(WebhookCallback.EventTriggerEnum.MANAGEMENT)
                ));

        // 4) Wallet polls transaction_id again → should eventually yield issuance
        cleanIssuerCallbacks();
        wallet.getCredentialFromTransactionId(apiVersion, entry);

        // Depending on implementation, you may need to poll again until the VC is returned.
        // If your wallet method already handles the polling, this is fine.
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.ISSUED);

        awaitStableIssuerCallbacks();
        WebhookCallbackAssert.assertThat(issuerCallbacks())
                .hasLastCallbacksInOrder(List.of(
                        new WebhookCallback()
                                .subjectId(offer.getOfferId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event("ISSUED")
                                .eventTrigger(WebhookCallback.EventTriggerEnum.OFFER),
                        new WebhookCallback()
                                .subjectId(offer.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event("ISSUED")
                                .eventTrigger(WebhookCallback.EventTriggerEnum.MANAGEMENT)
                ));

        // Optionnel: vérifier que les credentials sont bien émis et corrects
        SdJwtBatchAssert.assertThat(entry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);
    }
}
