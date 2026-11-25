package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.issuer.model.WebhookCallback;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.webhook_callback.WebhookCallbackAssert;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.util.List;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.STRICT)
class IssuerCallbacksTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-764",
            summary = "ManagementEntity lifecycle covers issue, suspend, reissue and revoke",
            description = """
                This test validates that all credential lifecycle transitions triggered by management
                behave correctly from issuance to suspension, reactivation and revocation.
                It also verifies idempotent behavior and isolation between multiple credentials.
                """
    )
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC},
            reason = "The new callbacks are not available yet."
    )
    @Tag(ReportingTags.HAPPY_PATH)
    @Tag(ReportingTags.UCI_C3_UPDATE_THE_STATUS_OF_AN_OFFER_OR_VC)
    @Tag(ReportingTags.UCI_I1D_CREATE_WEBHOOK_STATUS_CHANGE)
    void managementEntity_fullLifecycle_shouldHandleIssueSuspendReissueAndRevoke() {
        // Given
        wallet.setUseDPoP(true);
        final CredentialWithDeeplinkResponse offer1 =
                issuerManager.createCredentialWithSignedJwt(jwtKey, keyId, CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        cleanIssuerCallbacks();

        // When
        wallet.collectOffer(toUri(offer1.getOfferDeeplink()));
        issuerManager.verifyStatus(offer1.getManagementId(), CredentialStatusType.ISSUED);
        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer1.getManagementId(), UpdateCredentialStatusRequestType.SUSPENDED);
        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer1.getManagementId(), UpdateCredentialStatusRequestType.ISSUED);
        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer1.getManagementId(), UpdateCredentialStatusRequestType.ISSUED);
        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer1.getManagementId(), UpdateCredentialStatusRequestType.REVOKED);
        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer1.getManagementId(), UpdateCredentialStatusRequestType.REVOKED);

        // Then
        awaitStableIssuerCallbacks();
        WebhookCallbackAssert.assertThat(issuerCallbacks())
                .hasSizeEventually(6)
                .hasLastCallbacksInOrder(List.of(
                        new WebhookCallback()
                                .subjectId(offer1.getOfferId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.IN_PROGRESS.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_OFFER),
                        List.of(
                            new WebhookCallback()
                                    .subjectId(offer1.getOfferId())
                                    .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                    .event(CredentialStatusType.ISSUED.getValue())
                                    .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_OFFER),
                            new WebhookCallback()
                                    .subjectId(offer1.getManagementId())
                                    .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                    .event(CredentialStatusType.ISSUED.getValue())
                                    .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_MANAGEMENT)
                        ),
                        new WebhookCallback()
                                .subjectId(offer1.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.SUSPENDED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_MANAGEMENT),
                        new WebhookCallback()
                                .subjectId(offer1.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.ISSUED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_MANAGEMENT),
                        new WebhookCallback()
                                .subjectId(offer1.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.REVOKED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_MANAGEMENT)
                ));

        // Given
        final CredentialWithDeeplinkResponse offer2 =
                issuerManager.createCredentialWithSignedJwt(jwtKey, keyId, CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        cleanIssuerCallbacks();

        // When
        wallet.collectOffer(toUri(offer2.getOfferDeeplink()));
        issuerManager.verifyStatus(offer2.getManagementId(), CredentialStatusType.ISSUED);
        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer2.getManagementId(), UpdateCredentialStatusRequestType.SUSPENDED);
        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer2.getManagementId(), UpdateCredentialStatusRequestType.SUSPENDED);
        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer2.getManagementId(), UpdateCredentialStatusRequestType.REVOKED);

        // Then
        awaitStableIssuerCallbacks();
        WebhookCallbackAssert.assertThat(issuerCallbacks())
                .hasSizeEventually(5)
                .hasLastCallbacksInOrder(List.of(
                        new WebhookCallback()
                                .subjectId(offer2.getOfferId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.IN_PROGRESS.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_OFFER),
                        List.of(
                            new WebhookCallback()
                                    .subjectId(offer2.getOfferId())
                                    .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                    .event(CredentialStatusType.ISSUED.getValue())
                                    .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_OFFER),
                            new WebhookCallback()
                                    .subjectId(offer2.getManagementId())
                                    .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                    .event(CredentialStatusType.ISSUED.getValue())
                                    .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_MANAGEMENT)
                        ),
                        new WebhookCallback()
                                .subjectId(offer2.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.SUSPENDED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_MANAGEMENT),
                        new WebhookCallback()
                                .subjectId(offer2.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.REVOKED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_MANAGEMENT)
                ));
    }
}
