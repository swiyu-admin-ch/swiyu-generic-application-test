package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

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
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.webhook_callback.WebhookCallbackAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.JwtProof;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.nimbusds.jose.jwk.ECKey;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.HttpClientErrorException;

import java.security.KeyPair;
import java.util.List;
import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@ActiveProfiles({"issuer-strict"})
public class IssuerCallbacksTest extends BaseTest {

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
    public void managementEntity_fullLifecycle_shouldHandleIssueSuspendReissueAndRevoke() {
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
                        new WebhookCallback()
                                .subjectId(offer1.getOfferId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.ISSUED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_OFFER),
                        new WebhookCallback()
                                .subjectId(offer1.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.ISSUED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_MANAGEMENT),
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
                        new WebhookCallback()
                                .subjectId(offer2.getOfferId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.ISSUED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_OFFER),
                        new WebhookCallback()
                                .subjectId(offer2.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.ISSUED.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_MANAGEMENT),
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

    @Test
    @XrayTest(
            key = "EIDOMNI-773",
            summary = "ISSUANCE_ERROR callback triggered on key binding validation failure",
            description = """
                    This test validates that the issuer triggers an ISSUANCE_ERROR webhook callback when a credential issuance fails due to a key binding error.
                    
                    The wallet intentionally sends invalid proofs signed with incorrect keys during the credential collection process.
                    The issuer must reject the request and return an HTTP 400 error.
                    """)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "The fix is not available yet"
    )
    void givenCredentialOffer_whenWalletSendsInvalidKeyBindingProofs_thenIssuerTriggersIssuanceErrorCallback() {

        wallet.setUseDPoP(true);
        cleanIssuerCallbacks();
        // Given
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialWithSignedJwt(jwtKey, keyId,
                supportedMetadataId);
        final WalletBatchEntry entry = spy(wallet.createWalletBatchEntry());

        // When - Send too much proofs to the issuer
        doAnswer(invocation -> {
            entry.getProofs().clear();
            for (int i = 0; i < CredentialConfigurationFixtures.BATCH_SIZE + 1; i++) {
                entry.getProofs().add(new JwtProof(
                        entry.getIssuerMetadata().getCredentialIssuer(),
                        wallet.collectCNonce(entry),
                        entry.getProofPublicJwk(),
                        ECCryptoSupport.generateECKeyPair()
                ));;
            }
            return null;
        }).when(entry).createProofs();

        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () ->
                wallet.collectOffer(entry, toUri(offer.getOfferDeeplink()))
        );

        assertThat(errorCode(ex)).isEqualTo(400);

        awaitStableIssuerCallbacks();
        WebhookCallbackAssert.assertThat(issuerCallbacks())
                .hasSizeEventually(2)
                .hasLastCallbacksInOrder(List.of(
                        new WebhookCallback()
                                .subjectId(offer.getOfferId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event(CredentialStatusType.IN_PROGRESS.getValue())
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_OFFER),
                        new WebhookCallback()
                                .subjectId(offer.getOfferId())
                                .eventType(WebhookCallback.EventTypeEnum.ISSUANCE_ERROR)
                                .event("KEY_BINDING_ERROR")
                                .eventTrigger(WebhookCallback.EventTriggerEnum.CREDENTIAL_OFFER)
                ));
    }
}
