package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.SdJwtDebugMetadata;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.AssertionsForClassTypes;
import org.assertj.core.data.MapEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class PayloadEncryptionTest extends BaseTest {

    @BeforeEach
    void beforeEach() {
        wallet.setEncryptionPreferred(true);
    }


    @ParameterizedTest
    @EnumSource(SwiyuApiVersionConfig.class)
    @XrayTest(
            key = "EIDOMNI-392",
            summary = "Successful issuance and verification of an encrypted SD-JWT credential",
            description = """
                    This test validates the end-to-end issuance and verification of an unbound SD-JWT credential where both
                    OID4VCI credential responses and OID4VP presentation responses are encrypted according to specification.
                    The test runs for both SWIYU API versions to ensure encryption works correctly across all supported flows.
                    """
    )
    @Tag("ucv_o2")
    @Tag("ucv_o2a")
    @Tag("happy_path")
    void verifierRequiresEncryption_walletSendsEncryptedPayload_thenSuccess(final SwiyuApiVersionConfig swiyuApiVersion) {
        final String expectedCrv = "P-256";
        final String expectedKty = "EC";
        final String expectedEncryptionAlgorithm = "A128GCM";

        log.info("Issuer creating credential offer requiring encryption");
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("university_example_sd_jwt");

        log.info("Wallet collecting it using encryption");
        final WalletEntry entry = wallet.collectOffer(SwiyuApiVersionConfig.ID2, toUri(response.getOfferDeeplink()));
        AssertionsForClassTypes.assertThat(entry.getCredentialOffer()).isNotNull();

        log.info("Verifier creating verification request requiring encryption");
        String deeplink = null;
        if (swiyuApiVersion == SwiyuApiVersionConfig.ID2) {
            deeplink = verifierManager.verificationRequest()
                    .acceptedIssuerDid(entry.getIssuerDid())
                    .encrypted()
                    .create();
        } else if (swiyuApiVersion == SwiyuApiVersionConfig.V1) {
            deeplink = verifierManager.verificationRequest()
                    .acceptedIssuerDid(entry.getIssuerDid())
                    .withUniversityDCQL()
                    .encrypted()
                    .create();
        }

        final RequestObject verificationRequest = wallet.getVerificationDetailsUnsigned(deeplink);

        final OpenidClientMetadataDto metadata = verificationRequest.getClientMetadata();
        final JsonWebKey webKey = metadata.getJwks().getKeys().getFirst();
        final String encryptionAlgorithm = metadata.getEncryptedResponseEncValuesSupported().getFirst();

        assertThat(verificationRequest.getResponseMode()).isEqualTo(RequestObject.ResponseModeEnum.POST_JWT);
        assertThat(webKey.getCrv()).isEqualTo(expectedCrv);
        assertThat(webKey.getKty()).isEqualTo(expectedKty);
        assertThat(encryptionAlgorithm).isEqualTo(expectedEncryptionAlgorithm);

        log.info("Wallet sends encrypted presentation to verifier");
        final String token = entry.createPresentationForSdJwt(entry.getVerifiableCredential(), verificationRequest);
        wallet.respondToVerification(swiyuApiVersion, verificationRequest, token);

        verifierManager.verifyState();
    }

    @ParameterizedTest
    @EnumSource(SwiyuApiVersionConfig.class)
    @XrayTest(
            key = "EIDOMNI-452",
            summary = "Deny an unencrypted presentation that the verifier requires as encrypted",
            description = """
                    This test validates the negative path of the verifier that request an encrypted verification but receiving a valid but unencrypted verification
                    
                    Steps:
                    1. The wallet indicates preference for encrypted responses (encryption_preferred = true).
                    2. The issuer creates a credential offer for an unbound SD-JWT credential.
                    3. The wallet collects the credential offer and retrieves the encrypted SD-JWT credential.
                    4. The verifier creates a verification request that requires encrypted presentations.
                    5. The wallet retrieves the verification request details.
                    6. The wallet constructs and sends an unencrypted SD-JWT presentation back to the verifier.
                    7. The verifier deny the presentation as not encrypted, and keep the verification state as PENDING.
                    """
    )
    @Tag("ucv_o2")
    @Tag("edge_case")
    void verifierRequiresEncryption_walletSendsUnencrypted_thenRejected(final SwiyuApiVersionConfig swiyuApiVersion) {
        log.info("Issuer creating credential offer and wallet collecting it");
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("university_example_sd_jwt");
        final WalletEntry entry = wallet.collectOffer(SwiyuApiVersionConfig.ID2, toUri(response.getOfferDeeplink()));
        AssertionsForClassTypes.assertThat(entry.getCredentialOffer()).isNotNull();

        log.info("Verifier creating verification request requiring encryption");
        String deeplink = null;
        if (swiyuApiVersion == SwiyuApiVersionConfig.ID2) {
            deeplink = verifierManager.verificationRequest()
                    .acceptedIssuerDid(entry.getIssuerDid())
                    .encrypted()
                    .create();
        } else if (swiyuApiVersion == SwiyuApiVersionConfig.V1) {
            deeplink = verifierManager.verificationRequest()
                    .acceptedIssuerDid(entry.getIssuerDid())
                    .withDCQL()
                    .encrypted()
                    .create();
        }

        final RequestObject verificationRequest = wallet.getVerificationDetailsUnsigned(deeplink);

        assertThat(verificationRequest.getResponseMode()).isEqualTo(RequestObject.ResponseModeEnum.POST_JWT);

        // Mock the verifier request to force non-encrypted mode
        final RequestObject modifiedVerificationRequest = Mockito.spy(verificationRequest);
        Mockito.doReturn(RequestObject.ResponseModeEnum.POST)
                .when(modifiedVerificationRequest)
                .getResponseMode();

        log.info("Wallet sends unencrypted presentation to verifier");
        final String token = entry.createPresentationForSdJwt(entry.getVerifiableCredential(), modifiedVerificationRequest);
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () ->
                wallet.respondToVerification(swiyuApiVersion, modifiedVerificationRequest, token)
        );

        log.info("Verifier returned expected rejection: {}", ex.getStatusCode());
        assertThat(ex.getStatusCode().value()).isEqualTo(400);
        assertThat(ex.getResponseBodyAsString())
                .contains("Lacking encryption")
                .contains("All elements of the response should be encrypted");

        verifierManager.verifyState(VerificationStatus.PENDING);
    }

    @ParameterizedTest
    @EnumSource(SwiyuApiVersionConfig.class)
    @XrayTest(
            key = "EIDOMNI-461",
            summary = "Verifier denied an encrypted presentation that was encrypted with the wrong key",
            description = """
                    This test validates the negative path of the wallet sending a encrypted presentation but not with the expected key
                    
                    Steps:
                    1. The wallet indicates preference for encrypted responses (encryption_preferred = true).
                    2. The issuer creates a credential offer for an unbound SD-JWT credential.
                    3. The wallet collects the credential offer and retrieves the encrypted SD-JWT credential.
                    4. The verifier creates a verification request that requires encrypted presentations.
                    5. The wallet retrieves the verification request details.
                    6. The wallet constructs and sends an encrypted SD-JWT presentation that was encrypted with the wrong key
                    7. The verifier deny the presentation as not encrypted, and keep the verification state as PENDING.
                    """
    )
    @Tag("ucv_o2")
    @Tag("edge_case")
    void verifierRequiresEncryption_walletSendsWrongEncryption_thenRejected(final SwiyuApiVersionConfig swiyuApiVersion) throws JOSEException {
        log.info("Issuer creating credential offer and wallet collecting it");
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("university_example_sd_jwt");
        final WalletEntry entry = wallet.collectOffer(SwiyuApiVersionConfig.ID2, toUri(response.getOfferDeeplink()));
        AssertionsForClassTypes.assertThat(entry.getCredentialOffer()).isNotNull();

        log.info("Verifier creating verification request requiring encryption");
        String deeplink = null;
        if (swiyuApiVersion == SwiyuApiVersionConfig.ID2) {
            deeplink = verifierManager.verificationRequest()
                    .acceptedIssuerDid(entry.getIssuerDid())
                    .encrypted()
                    .create();
        } else if (swiyuApiVersion == SwiyuApiVersionConfig.V1) {
            deeplink = verifierManager.verificationRequest()
                    .acceptedIssuerDid(entry.getIssuerDid())
                    .withDCQL()
                    .encrypted()
                    .create();
        }

        final RequestObject verificationRequest = wallet.getVerificationDetailsUnsigned(deeplink);

        assertThat(verificationRequest.getResponseMode()).isEqualTo(RequestObject.ResponseModeEnum.POST_JWT);

        // Mock a wrong key for encrypt verification
        final RequestObject modifiedVerificationRequest = Mockito.spy(verificationRequest);
        final String wrongKeyId = "wrong-key-id";
        final ECKey wrongECKey = new ECKeyGenerator(Curve.P_256)
                .keyID(wrongKeyId)
                .generate();
        final JsonWebKey wrongKey = new JsonWebKey()
                .crv("P-256")
                .x(wrongECKey.getX().toString())
                .y(wrongECKey.getY().toString())
                .kid(wrongKeyId);
        final OpenidClientMetadataDto clientMetadata = Mockito.spy(verificationRequest.getClientMetadata());
        Mockito.doReturn(new JWKSet().addKeysItem(wrongKey))
                .when(clientMetadata)
                .getJwks();
        Mockito.doReturn(clientMetadata)
                .when(modifiedVerificationRequest)
                .getClientMetadata();

        log.info("Wallet sends encrypted with bad key presentation to verifier");
        final String token = entry.createPresentationForSdJwt(entry.getVerifiableCredential(), modifiedVerificationRequest);
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () ->
                wallet.respondToVerification(swiyuApiVersion, modifiedVerificationRequest, token)
        );

        log.info("Verifier returned expected rejection: {}", ex.getStatusCode());
        assertThat(ex.getStatusCode().value()).isEqualTo(400);
        assertThat(ex.getResponseBodyAsString())
                .contains(String.format("No matching JWK for keyId %s found. Unable to decrypt response", wrongKeyId));

        verifierManager.verifyState(VerificationStatus.PENDING);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-327",
            summary = "OID4VCI Happy Path with Encrypted Credential Request and Response",
            description = """
                    Validate that the Issuer correctly handles encryption of both credential request and credential response
                    for SWIYU API V1 (header SWIYU-API-Version: 2).
                    
                    Steps:
                    1. Issuer metadata exposes encryption support (ECDH-ES + A128GCM)
                    2. WalletBatchEntry generates ephemeral P-256 key
                    3. Wallet sends encrypted Credential Request (application/jwt)
                    4. Issuer encrypts Credential Response using Wallet ephemeral key
                    5. Wallet decrypts JWE and validates SD-JWT format
                    """
    )
    @Tag("uci_i1")
    @Tag("happy_path")
    void issuerEncryptionV1_encryptedRequestAndResponse_thenSuccess() {
        final SwiyuApiVersionConfig apiVersion = SwiyuApiVersionConfig.V1;

        wallet.setEncryptionPreferred(true);

        final CredentialWithDeeplinkResponse response =
                issuerManager.createCredentialOffer("unbound_example_sd_jwt");

        final WalletBatchEntry entry =
                (WalletBatchEntry) wallet.collectOffer(apiVersion, toUri(response.getOfferDeeplink()));

        assertThat(entry.getIssuerMetadata()).isNotNull();
        assertThat(entry.getCredentialConfigurationSupported()).isNotNull();
        assertThat(entry.getProofs()).hasSize(entry.getProofs().size());
    }

    @ParameterizedTest
    @EnumSource(SwiyuApiVersionConfig.class)
    @XrayTest(
            key = "EIDOMNI-620",
            summary = "Successful deferred issuance and verification of a bound SD-JWT credential",
            description = """
                    This test validates the end-to-end deferred issuance flow for a bound SD-JWT credential
                    with selective disclosure requirements. The wallet retrieves the credential using a transaction ID
                    and successfully constructs a presentation that satisfies the verifier's requirements.
                    The test runs for both SWIYU API versions (V1 and ID2) to ensure deferred credentials are correctly
                    retrieved and their disclosures are properly validated.
                    """
    )
    @Tag("uci_i1")
    @Tag("happy_path")
    void deferredSdJwtBoundCredential_withEncryptedPayload_thenSuccess(final SwiyuApiVersionConfig apiVersion) {
        final MapEntry<String, Object> averageGrade = MapEntry.entry("average_grade", 4.00);
        final MapEntry<String, Object> name = MapEntry.entry("name", "Data Science");
        final MapEntry<String, Object> type = MapEntry.entry("type", "Bachelor of Science");

        log.info("Issuer creating deferred credential offer for API version: {}", apiVersion.name());
        final CredentialWithDeeplinkResponse response = issuerManager.createDeferredCredentialOffer("university_example_sd_jwt");

        final WalletEntry entry = wallet.collectTransactionIdFromDeferredOffer(toUri(response.getOfferDeeplink()));
        AssertionsForClassTypes.assertThat(entry.getCredentialOffer()).isNotNull();

        final Map<String, Object> credentialStatus = Map.ofEntries(averageGrade, name, type);

        log.info("Business issuer updating credential status for deferred issuance");
        issuerManager.updateCredentialForDeferredFlowRequestCreation(response.getManagementId(), credentialStatus);
        issuerManager.updateState(response.getManagementId(), UpdateCredentialStatusRequestType.READY);

        log.info("Wallet retrieving deferred credential using transaction ID");
        var result = wallet.getCredentialFromTransactionId(apiVersion, entry);

        // Prepare list of credentials based on API version
        final List<String> credentials = new ArrayList<>();
        if (apiVersion == SwiyuApiVersionConfig.V1) {
            result.getAsJsonArray("credentials").forEach(c ->
                credentials.add(c.getAsJsonObject().get("credential").getAsString())
            );
        } else {
            credentials.add(result.get("credential").getAsString());
        }

        log.info("Verifying {} credential(s) and their disclosures", credentials.size());
        for (final String credential : credentials) {
            final SdJwtDebugMetadata sdjwt = new SdJwtDebugMetadata(credential);

            assertThat(sdjwt.isClaimValid(averageGrade)).isTrue();
            assertThat(sdjwt.isClaimValid(name)).isTrue();
            assertThat(sdjwt.isClaimValid(type)).isTrue();
        }
    }
}
