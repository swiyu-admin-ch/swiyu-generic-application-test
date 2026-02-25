package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.issuer.model.WebhookCallback;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.webhook_callback.WebhookCallbackAssert;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

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
        wallet.collectOfferV1(toUri(offer1.getOfferDeeplink()));

        final CredentialWithDeeplinkResponse offer2 =
                issuerManager.createCredentialWithSignedJwt(jwtKey, keyId, CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        wallet.collectOfferV1(toUri(offer2.getOfferDeeplink()));

        cleanIssuerCallbacks();
        WebhookCallbackAssert.assertThat(issuerCallbacks())
                .hasSizeEventually(0);

        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer1.getManagementId(),
                UpdateCredentialStatusRequestType.SUSPENDED);

        awaitStableIssuerCallbacks();
        WebhookCallbackAssert.assertThat(issuerCallbacks())
                .hasSizeEventually(2)
                .hasLastCallbacksInOrder(List.of(
                        new WebhookCallback()
                                .subjectId(offer1.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event("SUSPENDED")
                                .eventDescription(null),
                        new WebhookCallback()
                                .subjectId(offer1.getManagementId())
                                .eventType(WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                                .event("SUSPENDED")
                                .eventDescription(null)
                ))
        ;

        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer1.getManagementId(), UpdateCredentialStatusRequestType.ISSUED);

        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer1.getManagementId(), UpdateCredentialStatusRequestType.REVOKED);

        issuerManager.updateStateWithSignedJwt(jwtKey, keyId, offer1.getManagementId(),
                UpdateCredentialStatusRequestType.REVOKED);

        issuerManager.verifyStatus(offer2.getManagementId(), CredentialStatusType.ISSUED);
    }

}
