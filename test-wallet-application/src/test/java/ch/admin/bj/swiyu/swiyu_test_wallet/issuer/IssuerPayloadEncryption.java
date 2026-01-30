package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
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
class IssuerPayloadEncryption extends BaseTest {

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
    @Tag("uci_i1")
    @Tag("happy_path")
    void payloadEncryptionCredentialIssuanceId2_withEncryptedPayload_thenSuccess(final boolean deferred) {
        // Given
        final SwiyuApiVersionConfig issuanceApiVersion = SwiyuApiVersionConfig.ID2;
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

        WalletEntry entry;
        if (deferred) {
            entry = wallet.collectTransactionIdFromDeferredOffer(issuanceApiVersion,
                    toUri(offer.getOfferDeeplink()));
            // Then
            assertThat(entry.getTransactionId()).isNotNull();

            // When
            issuerManager.updateCredentialForDeferredFlowRequestCreation(offer.getManagementId(), finalSubjectClaims);
            // Then
            issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.READY);

            // When
            final CredentialResponse credentialResponse = wallet.getCredentialFromTransactionId(issuanceApiVersion, entry);
            CredentialResponseAssert.assertThat(credentialResponse)
                    .isResponseEncrypted();
        } else {
            // When
            entry = wallet.collectOffer(issuanceApiVersion, toUri(offer.getOfferDeeplink()));
            IssuerMetadataAssert.assertThat(entry.getIssuerMetadata())
                    .requiresCredentialRequestEncryption()
                    .requiresCredentialResponseEncryption()
                    .supportsCredentialRequestEncryption(List.of("A128GCM"), List.of("DEF"))
                    .supportsCredentialResponseEncryption(List.of("ECDH-ES"), List.of("A128GCM"), List.of("DEF"));
        }
        // Then
        SdJwtAssert.assertThat(entry.getVerifiableCredential())
                .hasExactlyInAnyOrderDisclosures(finalSubjectClaims);
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.ISSUED);
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
    @Tag("uci_i1")
    @Tag("happy_path")
    void payloadEncryptionCredentialIssuanceV1_withEncryptedPayload_thenSuccess(final boolean deferred) {
        // Given
        final SwiyuApiVersionConfig issuanceApiVersion = SwiyuApiVersionConfig.V1;
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
            batchEntry = (WalletBatchEntry) wallet.collectTransactionIdFromDeferredOffer(issuanceApiVersion,
                    toUri(offer.getOfferDeeplink()));
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
            batchEntry = (WalletBatchEntry) wallet.collectOffer(issuanceApiVersion, toUri(offer.getOfferDeeplink()));
        }
        // Then
        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(finalSubjectClaims);
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.ISSUED);
    }

    @ParameterizedTest
    @EnumSource(SwiyuApiVersionConfig.class)
    @XrayTest(key = "EIDOMNI-629", summary = "Deferred credential with encryption key mismatch between credential request and deferred call", description = """
            This test validates that deferred credentials are correctly encrypted with the ephemeral key
            used at the time of the deferred credential request, even if different from the initial credential request key.
            """)
    @Tag("uci_i1")
    @Tag("edge_case")
    void deferredCredentialEncryption_whenKeyMismatch_thenRejected(final SwiyuApiVersionConfig apiVersion) {
        // Given
        final Map<String, Object> initialSubjectClaims = CredentialSubjectFixtures.mandatoryClaimsEmployeeProfile();
        final Map<String, Object> updatedSubjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createDeferredCredentialOffer(supportedMetadataId,
                initialSubjectClaims);
        final WalletEntry entry = wallet.collectTransactionIdFromDeferredOffer(apiVersion,
                toUri(offer.getOfferDeeplink()));
        issuerManager.updateCredentialForDeferredFlowRequestCreation(offer.getManagementId(), updatedSubjectClaims);
        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.READY);
        // Then
        assertThat(entry.getTransactionId()).isNotNull();

        // Given
        final ECKey originalKey = entry.getEphemeralEncryptionKey();
        entry.generateEphemeralEncryptionKey();
        final ECKey newKey = entry.getEphemeralEncryptionKey();
        assertThat(newKey).as("New ephemeral key should be different from original key").isNotEqualTo(originalKey);

        // When
        final RuntimeException ex = assertThrows(RuntimeException.class,
                () -> wallet.getCredentialFromTransactionId(apiVersion, entry));

        // Then
        assertThat(ex.getCause())
                .isInstanceOf(com.nimbusds.jose.JOSEException.class);
        assertThat(ex.getCause().getMessage())
                .contains("Tag mismatch");
    }

    @ParameterizedTest
    @EnumSource(SwiyuApiVersionConfig.class)
    @XrayTest(key = "EIDOMNI-629", summary = "Deferred credential with encryption key mismatch between credential request and deferred call", description = """
            This test validates that deferred credentials are correctly encrypted with the ephemeral key
            used at the time of the deferred credential request, even if different from the initial credential request key.
            """)
    @Tag("uci_i1")
    @Tag("edge_case")
    void deferredCredentialEncryption_whenTransactionNotIssued_thenRejected(final SwiyuApiVersionConfig apiVersion) {
        // Given
        final Map<String, Object> initialSubjectClaims = CredentialSubjectFixtures.mandatoryClaimsEmployeeProfile();
        final Map<String, Object> updatedSubjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createDeferredCredentialOffer(supportedMetadataId,
                initialSubjectClaims);
        final WalletEntry entry = wallet.collectTransactionIdFromDeferredOffer(apiVersion,
                toUri(offer.getOfferDeeplink()));
        issuerManager.updateCredentialForDeferredFlowRequestCreation(offer.getManagementId(), updatedSubjectClaims);
        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.READY);
        // Then
        assertThat(entry.getTransactionId()).isNotNull();

        // Given
        final UUID invalidTransactionId = UUID.randomUUID();
        assertThat(invalidTransactionId).as("Invalid transaction should be different from existing transaction").isNotEqualTo(entry.getTransactionId());
        entry.setTransactionId(invalidTransactionId);

        // When
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class,
                () -> wallet.getCredentialFromTransactionId(apiVersion, entry));

        // Then
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasError("INVALID_TRANSACTION_ID")
                .hasErrorDescription("Invalid transactional id");
    }
}
