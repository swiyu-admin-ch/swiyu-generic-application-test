package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.request_object.RequestObjectAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierPayloadEncryptionTest extends BaseTest {

    @BeforeEach
    void beforeEach() {
        wallet.setUseEncryption(true);
    }

    @ParameterizedTest
    @ValueSource(strings = {CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT,
            CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT})
    @XrayTest(
            key = "EIDOMNI-392",
            summary = "Successful DCQL verification with payload encryption when wallet responds with encrypted presentation",
            description = """
                    This test validates the end-to-end DCQL verification flow when the Business Verifier requests payload encryption.
                    The Wallet retrieves the verification request and successfully constructs an encrypted presentation that satisfies the Verifier's encryption requirements.
                    The test runs for both bound and unbound SD-JWT credentials to ensure encryption works correctly across credential types.
                    """
    )
    @Tag("ucv_o2")
    @Tag("ucv_o2a")
    @Tag("happy_path")
    @DisableIfImageTag(
            issuer = {"stable", "staging", "rc"},
            reason = "The fix about alg in jwk keys is not yet available on disabled tags"
    )
    void verifyDCQL_whenEncryptionRequired_thenSuccess(final String supportedMetadataId) {
        final String expectedAlgorithm = "ECDH-ES";
        final String expectedKeyType = "EC";
        final String expectedCurve = "P-256";
        final String expectedEncAlgorithm = "A128GCM";

        // Given
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId, subjectClaims);
        final boolean holderBindingRequired =
                supportedMetadataId.equalsIgnoreCase(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final WalletBatchEntry batchEntry = (WalletBatchEntry) wallet.collectOffer(SwiyuApiVersionConfig.V1, toUri(offer.getOfferDeeplink()));

        // When
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(holderBindingRequired)
                .encrypted()
                .createManagementResponse();
        final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(verification.getVerificationDeeplink());

        // Then
        RequestObjectAssert.assertThat(verificationDetails)
                .hasDcqlQuery()
                .hasResponseMode(RequestObject.ResponseModeEnum.POST_JWT)
                .hasClientMetadata()
                .hasEncryptionJwks()
                .hasEncryptionJwksWithAlgorithm(expectedAlgorithm)
                .hasEncryptionJwksWithKty(expectedKeyType)
                .hasEncryptionJwksWithCurve(expectedCurve)
                .hasEncryptionEncAlgorithm(expectedEncAlgorithm)
                .hasVpFormats();

        // When
        String presentation;
        if (holderBindingRequired) {
            presentation = batchEntry.createPresentationForSdJwtIndex(0, verificationDetails);
        } else {
            presentation = batchEntry.getVerifiableCredential(0);
        }
        wallet.respondToVerification(SwiyuApiVersionConfig.V1, verificationDetails, presentation);

        // Then
        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
    }

    @ParameterizedTest
    @ValueSource(strings = {CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT,
            CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT})
    @XrayTest(
            key = "EIDOMNI-452",
            summary = "Reject unencrypted presentation when Business Verifier requires encrypted payload (ID2 retrocompatible)",
            description = """
                    This test validates that the Verifier rejects unencrypted presentations when the Business Verifier explicitly requests encrypted payloads.
                    The Wallet intentionally sends an unencrypted presentation to verify the Verifier enforces encryption requirements.
                    The verification state remains PENDING as the presentation does not meet security requirements.
                    """
    )
    @Tag("ucv_o2")
    @Tag("edge_case")
    @Deprecated(forRemoval = true)
    void rejectPresentation_whenWalletSendsUnencryptedAndEncryptionRequired_thenRejected(final String supportedMetadataId) {
        // Given
        final SwiyuApiVersionConfig swiyuApiVersion = SwiyuApiVersionConfig.ID2;
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId, subjectClaims);
        final boolean holderBindingRequired =
                supportedMetadataId.equalsIgnoreCase(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final WalletBatchEntry batchEntry = (WalletBatchEntry) wallet.collectOffer(SwiyuApiVersionConfig.V1, toUri(offer.getOfferDeeplink()));

        // When
        final ManagementResponse verification = verifierManager.verificationRequest(holderBindingRequired)
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .encrypted()
                .createManagementResponse();
        final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(verification.getVerificationDeeplink());

        RequestObjectAssert.assertThat(verificationDetails)
                .hasResponseMode(RequestObject.ResponseModeEnum.POST_JWT);

        // Given
        String presentation;
        if (holderBindingRequired) {
            presentation = batchEntry.createPresentationForSdJwtIndex(0, verificationDetails);
        } else {
            presentation = batchEntry.getVerifiableCredential(0);
        }

        // When - Wallet will not encrypt the payload for the next request
        wallet.setUseEncryption(false);
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () ->
                wallet.respondToVerification(swiyuApiVersion, verificationDetails, presentation)
        );

        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasErrorDescription("Lacking encryption. All elements of the response should be encrypted.");

        verifierManager.verifyState(VerificationStatus.PENDING);
    }

    @ParameterizedTest
    @ValueSource(strings = {CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT,
            CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT})
    @XrayTest(
            key = "EIDOMNI-452",
            summary = "Reject unencrypted DCQL presentation when Business Verifier requires encrypted payload",
            description = """
                    This test validates that the Verifier rejects unencrypted DCQL presentations when the Business Verifier explicitly requests encrypted payloads.
                    The Wallet intentionally sends an unencrypted DCQL-based presentation to verify the Verifier enforces encryption requirements.
                    The verification state remains PENDING as the presentation does not meet security requirements.
                    """
    )
    @Tag("ucv_o2")
    @Tag("edge_case")
    void rejectDCQLPresentation_whenWalletSendsUnencryptedAndEncryptionRequired_thenRejected(final String supportedMetadataId) {
        // Given
        final SwiyuApiVersionConfig swiyuApiVersion = SwiyuApiVersionConfig.V1;
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId, subjectClaims);
        final boolean holderBindingRequired =
                supportedMetadataId.equalsIgnoreCase(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final WalletBatchEntry batchEntry = (WalletBatchEntry) wallet.collectOffer(SwiyuApiVersionConfig.V1, toUri(offer.getOfferDeeplink()));

        // When
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(holderBindingRequired)
                .encrypted()
                .createManagementResponse();
        final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(verification.getVerificationDeeplink());

        RequestObjectAssert.assertThat(verificationDetails)
                .hasResponseMode(RequestObject.ResponseModeEnum.POST_JWT);

        // Given
        String presentation;
        if (holderBindingRequired) {
            presentation = batchEntry.createPresentationForSdJwtIndex(0, verificationDetails);
        } else {
            presentation = batchEntry.getVerifiableCredential(0);
        }

        // When - Wallet will not encrypt the payload for the next request
        wallet.setUseEncryption(false);
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () ->
                wallet.respondToVerification(swiyuApiVersion, verificationDetails, presentation)
        );

        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasErrorDescription("Lacking encryption. All elements of the response should be encrypted.");

        verifierManager.verifyState(VerificationStatus.PENDING);
    }

    @ParameterizedTest
    @ValueSource(strings = {CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT,
            CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT})
    @XrayTest(
            key = "EIDOMNI-461",
            summary = "Reject encrypted presentation when encrypted with wrong key (ID2 retrocompatible)",
            description = """
                    This test validates that the Verifier rejects presentations encrypted with an incorrect key that does not match the Business Verifier's public keys.
                    The Wallet sends a properly encrypted presentation but using a wrong encryption key to verify the Verifier enforces key validation.
                    The verification state remains PENDING as the presentation cannot be decrypted with the expected keys.
                    """
    )
    @Tag("ucv_o2")
    @Tag("edge_case")
    @Deprecated(forRemoval = true)
    void rejectPresentation_whenWalletEncryptsWithWrongKey_thenRejected(final String supportedMetadataId) throws JOSEException {
        // Given
        final SwiyuApiVersionConfig swiyuApiVersion = SwiyuApiVersionConfig.ID2;
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId, subjectClaims);
        final boolean holderBindingRequired =
                supportedMetadataId.equalsIgnoreCase(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final WalletBatchEntry batchEntry = (WalletBatchEntry) wallet.collectOffer(SwiyuApiVersionConfig.V1, toUri(offer.getOfferDeeplink()));

        // When
        final ManagementResponse verification = verifierManager.verificationRequest(holderBindingRequired)
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .encrypted()
                .createManagementResponse();
        final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(verification.getVerificationDeeplink());

        RequestObjectAssert.assertThat(verificationDetails)
                .hasResponseMode(RequestObject.ResponseModeEnum.POST_JWT);

        // Given
        String presentation;
        if (holderBindingRequired) {
            presentation = batchEntry.createPresentationForSdJwtIndex(0, verificationDetails);
        } else {
            presentation = batchEntry.getVerifiableCredential(0);
        }

        // When - Wallet will encrypt the payload but with the wrong key
        final RequestObject modifiedVerificationRequest = Mockito.spy(verificationDetails);
        final String wrongKeyId = "wrong-key-id";
        final ECKey wrongECKey = new ECKeyGenerator(Curve.P_256).keyID(wrongKeyId).generate();
        final JsonWebKey wrongKey = new JsonWebKey()
                .crv("P-256")
                .alg("ECDH-ES")
                .x(wrongECKey.getX().toString())
                .y(wrongECKey.getY().toString())
                .kid(wrongKeyId);

        final OpenidClientMetadataDto clientMetadata = Mockito.spy(verificationDetails.getClientMetadata());
        Mockito.doReturn(new JWKSet().addKeysItem(wrongKey))
                .when(clientMetadata)
                .getJwks();
        Mockito.doReturn(clientMetadata)
                .when(modifiedVerificationRequest)
                .getClientMetadata();

        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () ->
                wallet.respondToVerification(swiyuApiVersion, modifiedVerificationRequest, presentation)
        );

        // Then
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasErrorDescription(String.format("No matching JWK for keyId %s found. Unable to decrypt response.",
                        wrongKeyId));
        verifierManager.verifyState(VerificationStatus.PENDING);
    }

    @ParameterizedTest
    @ValueSource(strings = {CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT,
            CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT})
    @XrayTest(
            key = "EIDOMNI-461",
            summary = "Reject encrypted DCQL presentation when encrypted with wrong key",
            description = """
                    This test validates that the Verifier rejects DCQL presentations encrypted with an incorrect key that does not match the Business Verifier's public keys.
                    The Wallet sends a properly encrypted DCQL presentation but using a wrong encryption key to verify the Verifier enforces key validation.
                    The verification state remains PENDING as the presentation cannot be decrypted with the expected keys.
                    """
    )
    @Tag("ucv_o2")
    @Tag("edge_case")
    void rejectDCQLPresentation_whenWalletEncryptsWithWrongKey_thenRejected(final String supportedMetadataId) throws JOSEException {
        // Given
        final SwiyuApiVersionConfig swiyuApiVersion = SwiyuApiVersionConfig.V1;
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId, subjectClaims);
        final boolean holderBindingRequired =
                supportedMetadataId.equalsIgnoreCase(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final WalletBatchEntry batchEntry = (WalletBatchEntry) wallet.collectOffer(SwiyuApiVersionConfig.V1, toUri(offer.getOfferDeeplink()));

        // When
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(holderBindingRequired)
                .encrypted()
                .createManagementResponse();
        final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(verification.getVerificationDeeplink());

        RequestObjectAssert.assertThat(verificationDetails)
                .hasResponseMode(RequestObject.ResponseModeEnum.POST_JWT);

        // Given
        String presentation;
        if (holderBindingRequired) {
            presentation = batchEntry.createPresentationForSdJwtIndex(0, verificationDetails);
        } else {
            presentation = batchEntry.getVerifiableCredential(0);
        }

        // When - Wallet will encrypt the payload but with the wrong key
        final RequestObject modifiedVerificationRequest = Mockito.spy(verificationDetails);
        final String wrongKeyId = "wrong-key-id";
        final ECKey wrongECKey = new ECKeyGenerator(Curve.P_256).keyID(wrongKeyId).generate();
        final JsonWebKey wrongKey = new JsonWebKey()
                .crv("P-256")
                .alg("ECDH-ES")
                .x(wrongECKey.getX().toString())
                .y(wrongECKey.getY().toString())
                .kid(wrongKeyId);

        final OpenidClientMetadataDto clientMetadata = Mockito.spy(verificationDetails.getClientMetadata());
        Mockito.doReturn(new JWKSet().addKeysItem(wrongKey))
                .when(clientMetadata)
                .getJwks();
        Mockito.doReturn(clientMetadata)
                .when(modifiedVerificationRequest)
                .getClientMetadata();

        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () ->
                wallet.respondToVerification(swiyuApiVersion, modifiedVerificationRequest, presentation)
        );

        // Then
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasErrorDescription(String.format("No matching JWK for keyId %s found. Unable to decrypt response.",
                        wrongKeyId));
        verifierManager.verifyState(VerificationStatus.PENDING);
    }
}
