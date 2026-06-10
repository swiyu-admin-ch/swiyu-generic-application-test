package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.ConfigurationOverride;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.gen.issuer.model.StatusListUpdate;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.mockserver.model.HttpRequest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.awaitility.Awaitility.await;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockserver.model.HttpRequest.request;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@ActiveProfiles({"issuer-hsm"})
@Slf4j
@EnabledIfSystemProperty(
        named = "hsm",
        matches = "true",
        disabledReason = "HSM tests require -Dhsm=true so SoftHSM is injected only when explicitly requested."
)
public class IssuerHSMTest extends BaseTest {

    private static final String STATUS_REGISTRY_UPDATE_PATH =
            "/api/v1/status/business-entities/.*/status-list-entries/.*";
    private static final String INITIAL_HSM_KEY_ID = "01";
    private static final String ROTATED_HSM_KEY_ID = "02";
    private static final String HSM_KEY_PIN = "1234";

    @Test
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
            key = "EIDOMNI-831",
            summary = "Issuer updates HSM-backed status list with configuration override key",
            description = """
                    This test validates that the Business Issuer management API uses the ConfigurationOverride
                    from a status-list update request when publishing the HSM-backed status list to the registry.
                    """
    )
    @Tag(ReportingTags.UCI_C2)
    @Tag(ReportingTags.HAPPY_PATH)
    void statusListUpdate_withHsmConfigurationOverride_thenPublishesWithOverrideKey() throws Exception {
        // Given
        final StatusList statusList = issuerManager.createStatusList(10000, 2,
                new ConfigurationOverride()
                        .verificationMethod(issuerConfig.getIssuerAssertKeyId())
                        .keyId(INITIAL_HSM_KEY_ID)
                        .keyPin(HSM_KEY_PIN));
        final int updateCountBefore = countStatusRegistryUpdates();

        final StatusListUpdate updateRequest = new StatusListUpdate()
                .configurationOverride(new ConfigurationOverride()
                        .verificationMethod(issuerConfig.getIssuerAuthKeyId())
                        .keyId(ROTATED_HSM_KEY_ID)
                        .keyPin(HSM_KEY_PIN));

        // When
        final StatusList updatedStatusList = issuerManager.updateStatusListRegistryEntry(
                statusList.getId(),
                updateRequest);

        // Then
        assertThat(updatedStatusList.getId()).isEqualTo(statusList.getId());
        assertThat(updatedStatusList.getStatusRegistryUrl()).isEqualTo(statusList.getStatusRegistryUrl());

        await().untilAsserted(() -> assertThat(countStatusRegistryUpdates()).isGreaterThan(updateCountBefore));

        final SignedJWT publishedStatusList = parsePublishedStatusListJwt(lastStatusRegistryUpdate());
        assertThat(publishedStatusList.getHeader().getKeyID()).isEqualTo(issuerConfig.getIssuerAuthKeyId());
        assertThat(isSignedByHsmKey(publishedStatusList, ROTATED_HSM_KEY_ID))
                .as("status list update should be signed with the rotated HSM key from ConfigurationOverride")
                .isTrue();
        assertThat(isSignedByHsmKey(publishedStatusList, INITIAL_HSM_KEY_ID))
                .as("status list update should not keep using the creation/static HSM key")
                .isFalse();
    }

    private int countStatusRegistryUpdates() {
        return mockServerClient.retrieveRecordedRequests(statusRegistryUpdateRequest()).length;
    }

    private HttpRequest lastStatusRegistryUpdate() {
        final HttpRequest[] requests = mockServerClient.retrieveRecordedRequests(statusRegistryUpdateRequest());
        assertThat(requests).isNotEmpty();
        return requests[requests.length - 1];
    }

    private HttpRequest statusRegistryUpdateRequest() {
        return request()
                .withMethod("PUT")
                .withPath(STATUS_REGISTRY_UPDATE_PATH);
    }

    private SignedJWT parsePublishedStatusListJwt(final HttpRequest httpRequest) throws ParseException {
        final String body = httpRequest.getBodyAsString();
        assertThat(body).isNotBlank();

        if (body.contains(".")) {
            return SignedJWT.parse(body);
        }

        final String decodedBody = new String(Base64.getDecoder().decode(body), StandardCharsets.UTF_8);
        return SignedJWT.parse(decodedBody);
    }

    private boolean isSignedByHsmKey(final SignedJWT jwt, final String keyId) throws Exception {
        final String certificateResourcePath = "softhsm/keys/%s-cert.pem".formatted(keyId);
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(certificateResourcePath)) {
            assertThat(inputStream)
                    .as("HSM public certificate should be available: %s", certificateResourcePath)
                    .isNotNull();
            final String certificatePem = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
            return jwt.verify(new ECDSAVerifier(JWK.parseFromPEMEncodedX509Cert(certificatePem).toECKey()));
        }
    }
}
