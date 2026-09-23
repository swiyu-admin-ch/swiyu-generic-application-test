package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.jweutil.JweUtil;
import ch.admin.bj.swiyu.jweutil.JweUtilException;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
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
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.jwk.ECKey;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.ENCRYPTION)
class IssuerPayloadEncryptionTest extends BaseTest {

    private static final String ECDH_ES = "ECDH-ES";
    private static final String A128_GCM = "A128GCM";
    private static final String A256_GCM = "A256GCM";
    private static final String UNSUPPORTED_ENC = "A192GCM";
    private static final String DEF = "DEF";

    @BeforeEach
    void beforeEach() {
        wallet.setUseEncryption(true);
        wallet.setCredentialRequestEncryptionEnc(null);
        wallet.setCredentialResponseEncryptionEnc(null);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    @XrayTest(key = "EIDOMNI-1071", summary = "Successful issuer payload encryption with AES-256-GCM", description = """
            This test validates that the issuer advertises and honors A256GCM for OID4VCI payload encryption.
            The wallet encrypts the Credential Request with A256GCM and requests the Credential Response to use A256GCM.
            The encrypted response is asserted through its JWE header before the issued SD-JWT credentials are validated.
            """)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "A256GCM support is not available on these issuer tags"
    )
    void payloadEncryptionCredentialIssuance_whenA256GcmRequested_thenSuccess(final boolean deferred) {
        // Given
        wallet.setCredentialRequestEncryptionEnc(A256_GCM);
        wallet.setCredentialResponseEncryptionEnc(A256_GCM);

        final Map<String, Object> temporarySubjectClaims = CredentialSubjectFixtures.mandatoryClaimsEmployeeProfile();
        final Map<String, Object> finalSubjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = deferred
                ? issuerManager.createDeferredCredentialOffer(supportedMetadataId, temporarySubjectClaims)
                : issuerManager.createCredentialOffer(supportedMetadataId, finalSubjectClaims);

        final WalletBatchEntry batchEntry;
        final CredentialResponse credentialResponse;
        if (deferred) {
            batchEntry = wallet.collectTransactionIdFromDeferredOffer(toUri(offer.getOfferDeeplink()));

            // Then
            assertThat(batchEntry.getTransactionId()).isNotNull();
            CredentialResponseAssert.assertThat(batchEntry.getCredentialResponse())
                    .hasCode(202)
                    .isResponseEncryptedWithEnc(A256_GCM);

            // When
            issuerManager.updateCredentialForDeferredFlowRequestCreation(offer.getManagementId(), finalSubjectClaims);
            issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.READY);
            credentialResponse = wallet.getCredentialFromTransactionId(batchEntry);
        } else {
            batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
            credentialResponse = batchEntry.getCredentialResponse();
        }

        // Then
        IssuerMetadataAssert.assertThat(batchEntry.getIssuerMetadata())
                .supportsCredentialRequestEncryption(List.of(A128_GCM, A256_GCM), List.of(DEF))
                .supportsCredentialResponseEncryption(List.of(ECDH_ES), List.of(A128_GCM, A256_GCM), List.of(DEF))
                .requiresCredentialRequestEncryption()
                .requiresCredentialResponseEncryption();

        CredentialResponseAssert.assertThat(credentialResponse)
                .hasCode(200)
                .hasNotTransactionId()
                .hasNotInterval()
                .isResponseEncryptedWithEnc(A256_GCM);

        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(finalSubjectClaims);
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.ISSUED);
    }

    @Test
    @XrayTest(key = "EIDOMNI-1080", summary = "Reject issuer payload encryption with unencrypted JSON error response", description = """
            This test validates the issuer-side rejection boundaries for unsupported encryption methods and OID4VCI
            Section 8.3.1.2, which requires Credential Error Responses to remain unencrypted JSON responses.
            It first sends a Credential Request JWE with an unsupported enc header, then sends a valid encrypted
            Credential Request that asks for an unsupported Credential Response enc.
            """)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "A256GCM support is not available on these issuer tags"
    )
    void credentialRequestErrors_whenUnsupportedEncUsed_thenRejectedUnencrypted() {
        // Given
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        wallet.setCredentialRequestEncryptionEnc(UNSUPPORTED_ENC);
        wallet.setCredentialResponseEncryptionEnc(A256_GCM);
        final CredentialWithDeeplinkResponse unsupportedRequestEncOffer =
                issuerManager.createCredentialOffer(supportedMetadataId, subjectClaims);
        final HttpClientErrorException unsupportedRequestEnc = assertThrows(HttpClientErrorException.class,
                () -> wallet.collectOffer(toUri(unsupportedRequestEncOffer.getOfferDeeplink())));

        // Then
        ApiErrorAssert.assertThat(unsupportedRequestEnc)
                .hasStatus(400)
                .hasError("invalid_encryption_parameters");
        assertCredentialErrorResponseIsUnencryptedJson(unsupportedRequestEnc);
        assertThat(errorJson(unsupportedRequestEnc).get("error_description"))
                .contains("Unsupported encryption method")
                .contains(UNSUPPORTED_ENC);

        // When
        wallet.setCredentialRequestEncryptionEnc(A256_GCM);
        wallet.setCredentialResponseEncryptionEnc(UNSUPPORTED_ENC);
        final CredentialWithDeeplinkResponse unsupportedResponseEncOffer =
                issuerManager.createCredentialOffer(supportedMetadataId, subjectClaims);
        final HttpClientErrorException unsupportedResponseEnc = assertThrows(HttpClientErrorException.class,
                () -> wallet.collectOffer(toUri(unsupportedResponseEncOffer.getOfferDeeplink())));

        // Then
        ApiErrorAssert.assertThat(unsupportedResponseEnc)
                .hasStatus(400)
                .hasError("invalid_encryption_parameters");
        assertCredentialErrorResponseIsUnencryptedJson(unsupportedResponseEnc);
        assertThat(errorJson(unsupportedResponseEnc).get("error_description"))
                .contains("Requested encryption is not offered")
                .contains(UNSUPPORTED_ENC);
    }

    @Test
    @XrayTest(key = "EIDOMNI-1109", summary = "Credential error response is unencrypted when encryption parameters are missing", description = """
            This test validates OID4VCI Section 8.3.1.2 for an issuer profile that requires payload encryption.
            When the wallet sends a Credential Request without the required encryption parameters, the issuer must
            reject the request with invalid_encryption_parameters and return the Credential Error Response as
            unencrypted JSON.
            """)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC},
            reason = "The issuer rejects the unencrypted payload but trigger an internal server error waiting on @EIDOMNI-664"
    )
    void credentialRequest_whenEncryptionParametersMissing_thenCredentialErrorResponseIsUnencrypted() {
        // Given
        wallet.setUseEncryption(false);

        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId, subjectClaims);

        // When
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class,
                () -> wallet.collectOffer(toUri(offer.getOfferDeeplink())));

        // Then
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasError("invalid_encryption_parameters");
        assertCredentialErrorResponseIsUnencryptedJson(ex);
    }

    @Test
    @XrayTest(key = "EIDOMNI-1081", summary = "Reject encrypted issuer credential response decryption with wrong key", description = """
            This test validates that a Credential Response encrypted for the wallet cannot be read with a different
            ephemeral encryption key. The issuer returns an A256GCM JWE and the wallet proves that the encrypted
            payload is unreadable with the wrong key.
            """)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "A256GCM support is not available on these issuer tags"
    )
    void credentialResponse_whenDecryptedWithWrongKey_thenPayloadCannotBeRead() {
        // Given
        wallet.setCredentialRequestEncryptionEnc(A256_GCM);
        wallet.setCredentialResponseEncryptionEnc(A256_GCM);

        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId, subjectClaims);

        // When
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        // Then
        CredentialResponseAssert.assertThat(batchEntry.getCredentialResponse())
                .hasCode(200)
                .isResponseEncryptedWithEnc(A256_GCM);

        final ECKey originalKey = batchEntry.getEphemeralEncryptionKey();
        batchEntry.generateEphemeralEncryptionKey();
        final ECKey wrongKey = batchEntry.getEphemeralEncryptionKey();
        assertThat(wrongKey).as("Wrong decryption key must differ from the key used in the request").isNotEqualTo(originalKey);

        final JweUtilException ex = assertThrows(JweUtilException.class,
                () -> JweUtil.decrypt(batchEntry.getCredentialResponse().getRawBody(), wrongKey));
        assertThat(ex)
                .hasMessageContaining("Error during JWE decryption");
        assertThat(ex.getCause())
                .isInstanceOf(com.nimbusds.jose.JOSEException.class);

        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);
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
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This feature is not available yet"
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
                .hasError("invalid_transaction_id")
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
                .hasError("invalid_encryption_parameters")
                .hasErrorDescription(List.of("Request encryption is mandatory with content type set to application/jwt", "Request encryption is mandatory. Content type must be set to application/jwt"));
    }

    private static void assertCredentialErrorResponseIsUnencryptedJson(final HttpClientErrorException exception) {
        final String rawBody = exception.getResponseBodyAsString();

        assertThat(exception.getResponseHeaders())
                .as("Credential Error Response headers")
                .isNotNull();
        assertThat(exception.getResponseHeaders().getContentType())
                .as("Credential Error Response content type")
                .isNotNull()
                .satisfies(contentType ->
                        assertThat(MediaType.APPLICATION_JSON.isCompatibleWith(contentType)).isTrue());
        assertThat(rawBody)
                .as("Credential Error Response body")
                .isNotBlank();
        assertThat(rawBody.trim())
                .as("Credential Error Response body must be JSON, not a compact JWE")
                .startsWith("{")
                .endsWith("}");
        assertThatThrownBy(() -> JWEObject.parse(rawBody))
                .as("Credential Error Response must not be encrypted as JWE")
                .isInstanceOf(ParseException.class);
    }
}
