package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.ConfigurationOverride;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.gen.issuer.model.StatusListUpdate;
import ch.admin.bj.swiyu.gen.verifier.model.ConfigurationOverrideDto;
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
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.text.ParseException;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@ActiveProfiles({"issuer-hsm"})
@Slf4j
public class IssuerHSMTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-745",
            summary = "Todo",
            description = """
                    Todo
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    void updateStatusList_whenKeyMaterialOverrideConfiguration_thenSuccess() {
        // Given
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId,
                subjectClaims);
        final WalletBatchEntry entry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        // Then
        SdJwtBatchAssert.assertThat(entry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);

        // When
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(true)
                .createManagementResponse();
        final RequestObject verificationDetails = wallet
                .getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
        final String presentation = entry.createPresentationForSdJwtIndex(0, verificationDetails);
        wallet.respondToVerification(SwiyuApiVersionConfig.V1, verificationDetails, presentation);
        // Then
        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
    }

    /*
    @Test
    @Tag(ReportingTags.HAPPY_PATH)
    void updateStatusList_withConfigurationOverride_shouldUseDifferentKey() throws Exception {
        // GIVEN
        StatusList statusList = issuerManager.createStatusList(1000, 2);
        UUID statusListId = statusList.getId();

        // WHEN 1 — update WITHOUT override
        issuerManager.getStatusListApi().updateStatusListRegistryEntry(statusListId, null);

        awaitStableIssuerCallbacks();

        String jwtWithoutOverride = mockServerClientConfig.getLastStatusListJwt(statusListId);
        String kidWithout = extractKid(jwtWithoutOverride);

        log.info("KID without override: {}", kidWithout);

        // WHEN 2 — update WITH override
        StatusListUpdate update = new StatusListUpdate()
                .configurationOverride(
                        new ConfigurationOverride()
                                .keyId("override-key")
                );

        issuerManager.getStatusListApi().updateStatusListRegistryEntry(statusListId, update);

        awaitStableIssuerCallbacks();

        String jwtWithOverride = mockServerClientConfig.getLastStatusListJwt(statusListId);
        String kidWith = extractKid(jwtWithOverride);

        log.info("KID with override: {}", kidWith);

        assertThat(kidWith).isNotEqualTo(kidWithout);
    }

    private String extractKid(String jwt) throws ParseException {
        return SignedJWT.parse(jwt).getHeader().getKeyID();
    }

    @Test
    void updateStatusList_overrideShouldPersistAcrossCalls() throws Exception {
        //StatusList statusList = issuerManager.createStatusList(1000, 2);
        StatusList statusList = getCurrentStatusList();
        UUID id = statusList.getId();

        // Apply override
        StatusListUpdate update = new StatusListUpdate()
                .configurationOverride(new ConfigurationOverride().keyId("override-key"));

        issuerManager.getStatusListApi().updateStatusListRegistryEntry(id, update);

        String jwt1 = mockServerClientConfig.getLastStatusListJwt(id);
        String kid1 = extractKid(jwt1);

        // Call again WITHOUT override
        issuerManager.getStatusListApi().updateStatusListRegistryEntry(id, null);

        String jwt2 = mockServerClientConfig.getLastStatusListJwt(id);
        String kid2 = extractKid(jwt2);

        // STILL override key
        assertThat(kid2).isEqualTo(kid1);
    }
    */

    @Test
    @XrayTest(
            key = "EIDOMNI-393",
            summary = "Successful issuance and verification of a bound SD-JWT credential with selective disclosure",
            description = """
                    This test validates the immediate issuance of a bound SD-JWT credential that requires selective
                    disclosure during verification. The wallet constructs a derived presentation based on the verifier's
                    requirements and the credential is successfully validated.
                    """)
    @Tag(ReportingTags.UCI_C1A)
    @Tag(ReportingTags.UCI_I1A)
    @Tag(ReportingTags.UCV_O2A)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void hsmSetupTest() {
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
                    .getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
            verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
            final String presentation = batchEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            wallet.respondToVerification(SwiyuApiVersionConfig.V1, verificationDetails, presentation);
            // Then
            verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
        }
    }

}
