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
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.webhook_callback.WebhookCallbackAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.JwtProof;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.time.Duration;
import java.util.List;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertThrows;

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

    @Test
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Credential Issuer rejects an invalid jwt key proof without publishing an issuance error callback",
            description = """
                    Given a bound Credential Offer and its access token.
                    When the Wallet sends a jwt key proof for a different Credential Issuer.
                    Then the Credential Issuer returns HTTP 400 invalid_proof, leaves the offer in progress,
                    and delivers only the IN_PROGRESS callback from the token exchange.
                    Deviation: the jwt key proof aud differs from the Credential Issuer Identifier.
                    Spec: OID4VCI 1.0 §8.3.1 and Appendix F.1.
                    Regression: EIDOMNI-1394 defines the callback behavior.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCI_I1_ISSUING_VERIFIABLE_CREDENTIALS)
    @Tag(ReportingTags.UCI_I1A_CREATE_VERIFIABLE_CREDENTIALS)
    @Tag(ReportingTags.UCI_I1D_CREATE_WEBHOOK_STATUS_CHANGE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC},
            reason = "The issuer images predate the removal of KEY_BINDING_ERROR callbacks (EIDOMNI-1394)."
    )
    void credentialRequest_whenKeyProofAudienceIsWrong_thenRejectsWithoutIssuanceErrorCallback() {
        // Given
        wallet.setUseDPoP(true);
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialWithSignedJwt(
                jwtKey, keyId, CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final WalletBatchEntry entry = wallet.prepareOffer(toUri(offer.getOfferDeeplink()));
        entry.setProofsFromJwt(List.of(JwtProof.builder()
                .withAudience("https://another-credential-issuer.example")
                .cNonce(entry.getCNonce())
                .publicJwk(entry.getHolderPublicKeys().getFirst())
                .keyPair(entry.getHolderKeyPairs().getFirst())
                .attestationAuthority(wallet.getMockAttestationAuthority())
                .build()));

        // When
        final HttpClientErrorException rejection = assertThrows(
                HttpClientErrorException.class, () -> wallet.postCredentialRequest(entry)
        );

        // Then
        ApiErrorAssert.assertThat(rejection)
                .hasStatus(400)
                .hasError("invalid_proof");
        assertThat(entry.getIssuedCredentials())
                .isEmpty();
        assertThat(issuerManager.getCredentialOfferById(offer.getManagementId(), offer.getOfferId()).getStatus())
                .isEqualTo(CredentialStatusType.IN_PROGRESS);
        await()
                .during(Duration.ofSeconds(1))
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> assertThat(issuerCallbacks().stream()
                        .filter(callback -> offer.getOfferId().equals(callback.getSubjectId()))
                        .toList())
                        .singleElement()
                        .satisfies(callback -> {
                            assertThat(callback.getEventType())
                                    .isEqualTo(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED);
                            assertThat(callback.getEvent())
                                    .isEqualTo(CredentialStatusType.IN_PROGRESS.getValue());
                            assertThat(callback.getEventTrigger())
                                    .isEqualTo(WebhookCallback.EventTriggerEnum.CREDENTIAL_OFFER);
                        }));
    }
}
