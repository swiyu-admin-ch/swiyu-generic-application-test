package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
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
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.request_object.RequestObjectAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JwtSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
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
class VerifierOID4VPTest extends BaseTest {
    @Test
    @XrayTest(
            key = "EIDOMNI-554",
            summary = "Wallet retrieves a signed OID4VP request object from verifier",
            description = """
                    This test validates that the wallet can successfully retrieve a signed OpenID Connect
                    request object from the verifier containing verification query details, response information,
                    and cryptographic parameters required for the OID4VP flow.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1A)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "The images have not the state yet."
    )
    void walletFetchesSignedRequestObject_thenSuccess() {

        // GIVEN – verifier initiates verification (UCV_M1)
        final VerifierManager.VerificationRequestBuilder verifierManagerRequest = verifierManager
                .verificationRequest(true)
                .acceptedIssuerDid("did:swiyu:university")
                .withUniversity()
                .jwtSecure();
        final ManagementResponse managementResponse = verifierManagerRequest.createManagementResponse();

        // WHEN – wallet fetches request object (OID4VP)
        final String requestObjectJwt =
                wallet.getVerificationDetailSigned(managementResponse.getVerificationDeeplink());
        final JsonNode payload = JwtSupport.decodePayloadToJsonNode(requestObjectJwt);

        // THEN – signed request object (UCV_O1a)
        assertThat(requestObjectJwt)
                .as("OID4VP request object must be returned by the verifier")
                .isNotNull()
                .as("OID4VP request object must be returned as a compact JWT")
                .isNotBlank();

        assertThat(JwtSupport.isCompactJwt(requestObjectJwt))
                .as("OID4VP request object must be a compact JWS (header.payload.signature)")
                .isTrue();

        assertThat(payload.get("client_id"))
                .as("Request object must contain client_id")
                .isNotNull();

        assertThat(payload.get("client_id_scheme").asText())
                .as("Request object must contain did client_id_scheme")
                .isEqualTo("did");

        assertThat(payload.get("response_uri").asText())
                .as("Request object must contain response_uri")
                .isNotNull();

        assertThat(payload.get("response_uri").asText())
                .as("response_uri must point to the verifier OID4VP response endpoint")
                .contains(String.format("/oid4vp/api/request-object/%s/response-data", managementResponse.getId()));

        assertThat(payload.get("response_mode"))
                .as("Request object must define response_mode")
                .isNotNull();

        assertThat(payload.get("response_mode").asText())
                .as("response_mode must match verifier response mode configuration")
                .isEqualTo(
                        verifierManagerRequest.getRequest().getResponseMode().getValue()
                );

        assertThat(payload.get("nonce"))
                .as("Request object must contain a nonce")
                .isNotNull();

        assertThat(payload.get("state"))
                .as("Request object must contain a state")
                .isNotNull();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-555",
            summary = "Wallet retrieves an unsigned OID4VP request object from verifier",
            description = """
                    This test validates that the wallet can successfully retrieve an unsigned OpenID Connect
                    request object from the verifier containing DCQL-based verification query details, encrypted
                    response requirements, and necessary cryptographic parameters for the OID4VP flow.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1B)
    @Tag(ReportingTags.HAPPY_PATH)
    void walletFetchesUnsignedRequestObject_thenSuccess() {

        // GIVEN – verifier initiates verification (UCV_M1)
        final VerifierManager.VerificationRequestBuilder verifierManagerRequest = verifierManager
                .verificationRequest(false)
                .acceptedIssuerDid("did:swiyu:university")
                .withUniversityDCQL()
                .encrypted()
                .jwtUnsecure();
        final ManagementResponse managementResponse = verifierManagerRequest.createManagementResponse();

        // WHEN – wallet fetches request object (OID4VP)
        final RequestObject requestObject =
                wallet.getVerificationDetailsUnsigned(managementResponse.getVerificationDeeplink());

        // THEN – signed request object (UCV_O1a)
        assertThat(requestObject)
                .as("OID4VP request object must be returned by the verifier")
                .isNotNull();

        assertThat(requestObject.getClientId())
                .as("Request object must contain client_id")
                .isNotNull();

        assertThat(requestObject.getClientIdScheme())
                .as("Request object must contain did client_id_scheme")
                .isEqualTo("did");

        assertThat(requestObject.getResponseUri())
                .as("Request object must contain response_uri")
                .isNotNull();

        assertThat(requestObject.getResponseUri())
                .as("response_uri must point to the verifier OID4VP response endpoint")
                .contains(String.format("/oid4vp/api/request-object/%s/response-data", managementResponse.getId()));

        assertThat(requestObject.getResponseMode())
                .as("Request object must define response_mode")
                .isNotNull();

        assertThat(requestObject.getResponseMode().getValue())
                .as("response_mode must match verifier response mode configuration")
                .isEqualTo(verifierManagerRequest.getRequest().getResponseMode().getValue());

        assertThat(requestObject.getNonce())
                .as("Request object must contain a nonce")
                .isNotNull();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-795",
            summary = "Successful verification of an unbound SD-JWT credential with valid state",
            description = """
                    This test verifies that an unbound SD-JWT credential can be successfully presented and validated when the 
                    OAuth2 state returned by the wallet matches the state in the Request Object. The credential is issued 
                    through the OID4VCI flow and then presented to the verifier via OID4VP. The verification must complete 
                    successfully in both encrypted and non-encrypted payload modes.
                    """)
    @Tag(ReportingTags.UCI_C1A)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "This feature is not available yet"
    )
    void unboundNonDeferredCredential_whenValidState_thenSuccess() {
        // Given
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId,
                subjectClaims);
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        // Then
        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);

        // Given
        String verifiableCredential = batchEntry.getIssuedCredentials().get(0);
        ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(false)
                .createManagementResponse();
        RequestObject verificationDetails = wallet
                .getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
        RequestObjectAssert.assertThat(verificationDetails)
                .hasState();
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

        // When
        wallet.setUseEncryption(false);
        wallet.respondToVerification(verificationDetails, verifiableCredential);

        // Then
        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);

        // Given
        verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(false)
                .encrypted()
                .createManagementResponse();
        verificationDetails = wallet
                .getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
        RequestObjectAssert.assertThat(verificationDetails)
                .hasState();
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

        // When
        wallet.setUseEncryption(true);
        wallet.respondToVerification(verificationDetails, verifiableCredential);

        // Then
        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-797",
            summary = "Verification rejected when OAuth2 state mismatch occurs",
            description = """
                    This test verifies that the verifier rejects a credential presentation when the OAuth2 state returned by 
                    the wallet does not match the state defined in the Request Object. The wallet intentionally modifies the 
                    state before sending the presentation. The verifier must return an error and keep the verification in 
                    the PENDING state in both encrypted and non-encrypted payload modes.
                    """)
    @Tag(ReportingTags.UCI_C1A)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING, ImageTags.DEV},
            reason = "This feature is not available yet (Enable this test when // EIDOMNI-692: Remove the `|| true`)"
    )
    void unboundNonDeferredCredential_whenWrongState_thenRejected() {
        // Given
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId,
                subjectClaims);
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        // Then
        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);

        // Given
        String verifiableCredential = batchEntry.getIssuedCredentials().get(0);
        ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(false)
                .createManagementResponse();
        RequestObject verificationDetails = wallet
                .getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
        RequestObjectAssert.assertThat(verificationDetails)
                .hasState();
        final RequestObject verificationDetailsUnencryptedFaked = Mockito.spy(verificationDetails);
        Mockito.doReturn(verificationDetails.getState() + "wrong")
                .when(verificationDetailsUnencryptedFaked)
                .getState();
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

        // When
        wallet.setUseEncryption(false);
        HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
            wallet.respondToVerification(verificationDetailsUnencryptedFaked, verifiableCredential);
        });
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasErrorDescription("OAuth2.0 State mismatch. Expected to receive the state as in Request Object");

        // Then
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

        // Given
        verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL(false)
                .encrypted()
                .createManagementResponse();
        verificationDetails = wallet
                .getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
        RequestObjectAssert.assertThat(verificationDetails)
                .hasState();
        final RequestObject verificationDetailsEncryptedFaked = Mockito.spy(verificationDetails);
        Mockito.doReturn(verificationDetails.getState() + "wrong")
                .when(verificationDetailsEncryptedFaked)
                .getState();
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

        // When
        wallet.setUseEncryption(true);
        ex = assertThrows(HttpClientErrorException.class, () -> {
            wallet.respondToVerification(verificationDetailsEncryptedFaked, verifiableCredential);
        });
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasErrorDescription("OAuth2.0 State mismatch. Expected to receive the state as in Request Object");

        // Then
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
    }

}
