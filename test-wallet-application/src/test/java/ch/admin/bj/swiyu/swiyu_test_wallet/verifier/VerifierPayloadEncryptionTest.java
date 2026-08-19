package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.request_object.RequestObjectAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JWESupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.net.URI;
import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static ch.admin.bj.swiyu.swiyu_test_wallet.support.TestConstants.VERIFIER_URL;
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
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.UCV_O2A)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "The fix about alg in jwk keys is not yet available on disabled tags"
    )
    void verifyDCQL_whenEncryptionRequired_thenSuccess(final String supportedMetadataId) {
        final String expectedAlgorithm = "ECDH-ES";
        final String expectedKeyType = "EC";
        final String expectedCurve = "P-256";
        final String expectedEncAlgorithm = "A256GCM";

        // Given
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId, subjectClaims);
        final boolean holderBindingRequired =
                supportedMetadataId.equalsIgnoreCase(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        // When
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(holderBindingRequired)
                .encrypted()
                .createManagementResponse();
        final RequestObject verificationDetails = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());

        // Then
        RequestObjectAssert.assertThat(verificationDetails)
                .hasDcqlQuery()
                .hasResponseMode(ResponseModeType.DIRECT_POST_JWT)
                .hasState()
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
        wallet.respondToVerification(verificationDetails, presentation);

        // Then
        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
    }

    @ParameterizedTest(name = "[{index}] reject {0} decompression bomb")
    @EnumSource(JWESupport.DecompressionBombEncoding.class)
    @XrayTest(
            key = "EIDOMNI-1252",
            summary = "Verifier rejects oversized decompressed direct_post.jwt payloads",
            description = """
                    The Wallet follows the normal encrypted OID4VP direct_post.jwt flow but deliberately supplies a
                    highly compressible zip=DEF Authorization Response whose decompressed UTF-8 payload exceeds
                    21 MiB. ASCII and multibyte variants verify that the Verifier enforces a byte-size limit before
                    JSON and business processing, without changing the verification state or triggering a callback.
                    """
    )
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "JWE decompressed-payload limits are not available on these verifier tags"
    )
    void directPostJwtPayloadEncryption_whenDecompressedPayloadIsOversized_thenRejectedWithoutSideEffects(
            final JWESupport.DecompressionBombEncoding encoding
    ) {
        // Given
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(false)
                .encrypted()
                .createManagementResponse();
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
        final RequestObject requestObject = wallet.getVerificationRequestObject(
                verification.getVerificationDeeplink()
        );
        assertThat(requestObject.getResponseMode()).isEqualTo(ResponseModeType.DIRECT_POST_JWT);
        final int callbacksBefore = awaitStableVerifierCallbacks();
        final String prefix = "{\"error\":\"access_denied\",\"error_description\":\"";
        final String suffix = "\",\"state\":\"" + requestObject.getState() + "\"}";
        final String payload = JWESupport.createDecompressionBombPayload(prefix, suffix, encoding);

        // When
        final HttpClientErrorException exception = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.respondToVerificationWithEncryptedPayload(requestObject, payload)
        );

        // Then
        ApiErrorAssert.assertThat(exception)
                .hasStatus(400)
                .hasError("invalid_credential")
                .hasErrorDescription("Response cannot be decrypted.");
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
        awaitNoneVerifierCallback(callbacksBefore);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1108",
            summary = "Accept unencrypted wallet error response for direct_post.jwt",
            description = """
                    This test validates OID4VP Section 8.3.1 for Response Mode direct_post.jwt.
                    When the Wallet is unable to generate an encrypted Authorization Response, it may send an
                    unencrypted error response using direct_post. The Verifier must accept that error response
                    and close the verification as failed instead of rejecting it for missing encryption.
                    """
    )
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.EDGE_CASE)
    void rejectVerification_whenWalletSendsUnencryptedErrorForDirectPostJwt_thenAcceptedAsFailure() {
        // Given
        final String errorDescription = "Wallet cannot generate encrypted response";
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(false)
                .encrypted()
                .createManagementResponse();
        final URI responseUri = URI.create("%s/oid4vp/api/request-object/%s/response-data"
                .formatted(VERIFIER_URL, verification.getId()));
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

        final RequestObject verificationDetails = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());

        // When
        wallet.respondToVerificationWithError(responseUri, verificationDetails.getState(), "access_denied", errorDescription);

        // Then
        final ManagementResponse failedVerification =
                verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
        assertThat(failedVerification.getWalletResponse()).isNotNull();
        assertThat(failedVerification.getWalletResponse().getErrorCode())
                .isEqualTo(VerificationErrorResponseCode.ACCESS_DENIED);
        assertThat(failedVerification.getWalletResponse().getErrorDescription())
                .isEqualTo(errorDescription);
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
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "The stable tag is not yet ready with batch issuance."
    )
    void rejectDCQLPresentation_whenWalletSendsUnencryptedAndEncryptionRequired_thenRejected(final String supportedMetadataId) {
        // Given
        final SwiyuApiVersionConfig swiyuApiVersion = SwiyuApiVersionConfig.V1;
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId, subjectClaims);
        final boolean holderBindingRequired =
                supportedMetadataId.equalsIgnoreCase(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        // When
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(holderBindingRequired)
                .encrypted()
                .createManagementResponse();
        final RequestObject verificationDetails = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());

        RequestObjectAssert.assertThat(verificationDetails)
                .hasResponseMode(ResponseModeType.DIRECT_POST_JWT);

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
                wallet.respondToVerification(verificationDetails, presentation)
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
            summary = "Reject encrypted DCQL presentation when encrypted with wrong key",
            description = """
                    This test validates that the Verifier rejects DCQL presentations encrypted with an incorrect key that does not match the Business Verifier's public keys.
                    The Wallet sends a properly encrypted DCQL presentation but using a wrong encryption key to verify the Verifier enforces key validation.
                    The verification state remains PENDING as the presentation cannot be decrypted with the expected keys.
                    """
    )
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "The stable tag is not yet ready with batch issuance."
    )
    void rejectDCQLPresentation_whenWalletEncryptsWithWrongKey_thenRejected(final String supportedMetadataId) throws JOSEException {
        // Given
        final SwiyuApiVersionConfig swiyuApiVersion = SwiyuApiVersionConfig.V1;
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId, subjectClaims);
        final boolean holderBindingRequired =
                supportedMetadataId.equalsIgnoreCase(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        // When
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(holderBindingRequired)
                .encrypted()
                .createManagementResponse();
        final RequestObject verificationDetails = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());

        RequestObjectAssert.assertThat(verificationDetails)
                .hasResponseMode(ResponseModeType.DIRECT_POST_JWT);

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
                wallet.respondToVerification(modifiedVerificationRequest, presentation)
        );

        // Then
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasErrorDescription(String.format("No matching JWK for keyId %s found. Unable to decrypt response.",
                        wrongKeyId));
        verifierManager.verifyState(VerificationStatus.PENDING);
    }
}
