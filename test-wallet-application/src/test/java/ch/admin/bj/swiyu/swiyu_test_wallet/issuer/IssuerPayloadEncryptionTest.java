package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_response.CredentialResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_response.CredentialResponseAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.issuer_metadata.IssuerMetadataAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import com.nimbusds.jose.jwk.ECKey;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.HttpClientErrorException;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@ActiveProfiles("issuer-encryption")
class IssuerPayloadEncryptionTest extends BaseTest {

    @BeforeEach
    void beforeEach() {
        wallet.setUseEncryption(true);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    @XrayTest(key = "EIDOMNI-620", summary = "Successful deferred issuance and verification of a bound SD-JWT credential when components require encryption", description = """
            This test validates the end-to-end deferred issuance flow for a bound SD-JWT credential
            with selective disclosure requirements. The wallet retrieves the credential using a transaction ID
            and successfully constructs a presentation that satisfies the verifier's requirements.
            The test runs for both SWIYU API versions (V1 and ID2) to ensure deferred credentials are correctly
            retrieved and their disclosures are properly validated.
            """)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "The fix for supported media type not available yet"
    )
    void payloadEncryptionCredentialIssuanceV1_withEncryptedPayload_thenSuccess(final boolean deferred) {
        // Given
        final Map<String, Object> temporarySubjectClaims = CredentialSubjectFixtures.mandatoryClaimsEmployeeProfile();
        final Map<String, Object> finalSubjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        CredentialWithDeeplinkResponse offer;
        if (deferred) {
            offer = issuerManager.createDeferredCredentialOffer(supportedMetadataId, temporarySubjectClaims);
        } else {
            offer = issuerManager.createCredentialOffer(supportedMetadataId, finalSubjectClaims);
        }

        WalletBatchEntry batchEntry;
        if (deferred) {
            batchEntry = wallet.collectTransactionIdFromDeferredOffer(toUri(offer.getOfferDeeplink()));
            // Then
            assertThat(batchEntry.getTransactionId()).isNotNull();

            // When
            issuerManager.updateCredentialForDeferredFlowRequestCreation(offer.getManagementId(), finalSubjectClaims);
            // Then
            issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.READY);

            // When
            wallet.getCredentialFromTransactionId(batchEntry);
        } else {
            // When
            batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        }
        // Then
        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(finalSubjectClaims);
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.ISSUED);
    }

    @Test
    @XrayTest(key = "EIDOMNI-629", summary = "Deferred credential with encryption key mismatch between credential request and deferred call", description = """
            This test validates that deferred credentials are correctly encrypted with the ephemeral key
            used at the time of the deferred credential request, even if different from the initial credential request key.
            """)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void deferredCredentialEncryption_whenKeyMismatch_thenRejected() {
        // Given
        final Map<String, Object> initialSubjectClaims = CredentialSubjectFixtures.mandatoryClaimsEmployeeProfile();
        final Map<String, Object> updatedSubjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createDeferredCredentialOffer(supportedMetadataId,
                initialSubjectClaims);
        final WalletBatchEntry batchEntry =
                wallet.collectTransactionIdFromDeferredOffer(toUri(offer.getOfferDeeplink()));
        issuerManager.updateCredentialForDeferredFlowRequestCreation(offer.getManagementId(), updatedSubjectClaims);
        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.READY);
        // Then
        assertThat(batchEntry.getTransactionId()).isNotNull();

        // Given
        final ECKey originalKey = batchEntry.getEphemeralEncryptionKey();
        batchEntry.generateEphemeralEncryptionKey();
        final ECKey newKey = batchEntry.getEphemeralEncryptionKey();
        assertThat(newKey).as("New ephemeral key should be different from original key").isNotEqualTo(originalKey);

        // When
        final RuntimeException ex = assertThrows(RuntimeException.class,
                () -> wallet.getCredentialFromTransactionId(batchEntry));

        // Then
        assertThat(ex.getCause())
                .isInstanceOf(com.nimbusds.jose.JOSEException.class);
        assertThat(ex.getCause().getMessage())
                .contains("Tag mismatch");
    }

    @Test
    @XrayTest(key = "EIDOMNI-629", summary = "Deferred credential with encryption key mismatch between credential request and deferred call", description = """
            This test validates that deferred credentials are correctly encrypted with the ephemeral key
            used at the time of the deferred credential request, even if different from the initial credential request key.
            """)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC},
            reason = "Fix for deferred encryption is not available yet"
    )
    void deferredCredentialEncryption_whenTransactionNotIssued_thenRejected() {
        // Given
        final Map<String, Object> initialSubjectClaims = CredentialSubjectFixtures.mandatoryClaimsEmployeeProfile();
        final Map<String, Object> updatedSubjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createDeferredCredentialOffer(supportedMetadataId,
                initialSubjectClaims);
        final WalletBatchEntry batchEntry =
                wallet.collectTransactionIdFromDeferredOffer(toUri(offer.getOfferDeeplink()));
        issuerManager.updateCredentialForDeferredFlowRequestCreation(offer.getManagementId(), updatedSubjectClaims);
        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.READY);
        // Then
        assertThat(batchEntry.getTransactionId()).isNotNull();

        // Given
        final UUID invalidTransactionId = UUID.randomUUID();
        assertThat(invalidTransactionId).as("Invalid transaction should be different from existing transaction").isNotEqualTo(batchEntry.getTransactionId());
        batchEntry.setTransactionId(invalidTransactionId);

        // When
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class,
                () -> wallet.getCredentialFromTransactionId(batchEntry));

        // Then
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasError("INVALID_TRANSACTION_ID")
                .hasErrorDescription("Invalid transaction id");
    }

    @Test
    @XrayTest(key = "EIDOMNI-666",
            summary = "Deferred credential request rejected when encryption is required but wallet sends unencrypted",
            description = """
                    This test validates that a wallet cannot retrieve a deferred credential using an unencrypted request
                    when the strict issuer profile requires encryption.
                    """)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC},
            reason = "The issuer rejects the unencrypted payload but trigger an internal server error waiting on @EIDOMNI-664"
    )
    void deferredCredentialRequest_whenUnencryptedPayload_thenRejected() {
        // Given
        final Map<String, Object> initialSubjectClaims = CredentialSubjectFixtures.mandatoryClaimsEmployeeProfile();
        final Map<String, Object> updatedSubjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createDeferredCredentialOffer(supportedMetadataId,
                initialSubjectClaims);
        final WalletBatchEntry entry =
                wallet.collectTransactionIdFromDeferredOffer(toUri(offer.getOfferDeeplink()));
        issuerManager.updateCredentialForDeferredFlowRequestCreation(offer.getManagementId(), updatedSubjectClaims);
        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.READY);
        // Then
        assertThat(entry.getTransactionId()).isNotNull();

        // Given
        wallet.setUseEncryption(false);

        // When
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class,
                () -> wallet.getCredentialFromTransactionId(entry));
        // Then
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasError("INVALID_ENCRYPTION_PARAMETERS")
                .hasErrorDescription("Request encryption is mandatory with content type set to application/jwt");
    }
}
