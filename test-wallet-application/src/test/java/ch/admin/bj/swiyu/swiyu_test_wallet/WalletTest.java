package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialInfoResponse;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.CredentialOffer;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.issuance_deeplink.IssuanceDeeplinkAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_deeplink.VerificationDeeplinkAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.util.HashMap;
import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class WalletTest extends BaseTest {

    @BeforeEach
    void beforeEach() {
        wallet.setEncryptionPreferred(false);
    }

    @Test
    @XrayTest(key = "EIDOMNI-386", summary = "Successful verification of an unbound SD-JWT credential (non-deferred)", description = """
            This test validates the end-to-end issuance and verification of an unbound SD-JWT credential
            through immediate OID4VCI credential issuance and OID4VP-based verification. The wallet successfully
            collects the non-deferred credential and presents it to a verifier for validation.
            """)
    @Tag("uci_c1a")
    @Tag("uci_i1")
    @Tag("ucv_o2")
    @Tag("happy_path")
    void unboundNotDeferredCredential_thenSuccess() {
        // Given
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId,
                subjectClaims);
        final WalletEntry entry = wallet.collectOffer(SwiyuApiVersionConfig.ID2, toUri(offer.getOfferDeeplink()));
        // Then
        SdJwtAssert.assertThat(entry.getIssuerSdJwt())
                .hasExactlyInAnyOrderDisclosures(subjectClaims);

        // When
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(entry.getIssuerDid())
                .createManagementResponse();
        final RequestObject verificationRequest = wallet
                .getVerificationDetailsUnsigned(toUri(verification.getVerificationDeeplink()));
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
        wallet.respondToVerification(SwiyuApiVersionConfig.ID2, verificationRequest, entry.getVerifiableCredential());
        // Then
        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
    }

    @Test
    @XrayTest(key = "EIDOMNI-389", summary = "Successful deferred issuance and verification of an unbound SD-JWT credential", description = """
            This test validates the end-to-end deferred issuance flow for an unbound SD-JWT credential,
            where the wallet retrieves a transaction ID during the initial offer collection phase and
            collects the credential after the issuer marks it as READY. The credential is subsequently
            verified through the OID4VP interface.
            """)
    @Tag("uci_c1b")
    @Tag("uci_i1b")
    @Tag("ucv_o2")
    @Tag("happy_path")
    void unboundDeferredCredential_thenSuccess() {
        // Given
        final Map<String, Object> initialSubjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final Map<String, Object> updatedSubjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        updatedSubjectClaims.put(CredentialSubjectFixtures.NUMBER_MANDATORY_CLAIM_KEY, 15.0);
        updatedSubjectClaims.remove(CredentialSubjectFixtures.NUMBER_OPTIONAL_CLAIM_KEY);
        final String supportedMetadataId = CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse response = issuerManager.createDeferredCredentialOffer(supportedMetadataId,
                initialSubjectClaims);
        final WalletEntry entry = wallet.collectTransactionIdFromDeferredOffer(SwiyuApiVersionConfig.ID2,
                toUri(response.getOfferDeeplink()));
        // Then
        issuerManager.verifyStatus(response.getManagementId(), CredentialStatusType.DEFERRED);

        // When
        issuerManager.updateCredentialForDeferredFlowRequestCreation(response.getManagementId(), updatedSubjectClaims);
        issuerManager.updateState(response.getManagementId(), UpdateCredentialStatusRequestType.READY);
        wallet.getCredentialFromTransactionId(entry);
        // Then
        SdJwtAssert.assertThat(entry.getIssuerSdJwt())
                .hasExactlyInAnyOrderDisclosures(updatedSubjectClaims);

        // When
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(entry.getIssuerDid())
                .createManagementResponse();
        ;
        final RequestObject verificationDetails = wallet
                .getVerificationDetailsUnsigned(toUri(verification.getVerificationDeeplink()));
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
        wallet.respondToVerification(SwiyuApiVersionConfig.ID2, verificationDetails, entry.getVerifiableCredential());
        // Then
        issuerManager.verifyStatus(response.getManagementId(), CredentialStatusType.ISSUED);
    }

    @Test
    @XrayTest(key = "EIDOMNI-393", summary = "Successful issuance and verification of a bound SD-JWT credential with selective disclosure", description = """
            This test validates the immediate issuance of a bound SD-JWT credential that requires selective
            disclosure during verification. The wallet constructs a derived presentation based on the verifier's
            requirements and the credential is successfully validated.
            """)
    @Tag("uci_c1a")
    @Tag("uci_i1a")
    @Tag("ucv_o2a")
    @Tag("happy_path")
    void createBoundCredential_thenSuccess() throws InterruptedException {
        // Given
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.UNIVERSITY_EXAMPLE_SD_JWT;

        // When
        int nbCallbacks = awaitStableIssuerCallbacks();
        final CredentialWithDeeplinkResponse offer = issuerManager
                .createCredentialOffer(supportedMetadataId, subjectClaims);
        final WalletEntry entry = wallet.collectOffer(SwiyuApiVersionConfig.ID2, toUri(offer.getOfferDeeplink()));
        // Then
        awaitNIssuerCallback(nbCallbacks, 2);
        SdJwtAssert.assertThat(entry.getIssuerSdJwt())
                .hasExactlyInAnyOrderDisclosures(subjectClaims);

        // When
        nbCallbacks = awaitStableVerifierCallbacks();
        final ManagementResponse verification = verifierManager.verificationRequest(false).acceptedIssuerDid(entry.getIssuerDid())
                .withUniversity().createManagementResponse();
        final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(toUri(verification.getVerificationDeeplink()));
        final String res = entry.createPresentationForSdJwt(entry.getVerifiableCredential(), verificationDetails);
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
        wallet.respondToVerification(SwiyuApiVersionConfig.ID2, verificationDetails, res);
        // Then
        awaitOneVerifierCallback(nbCallbacks);
        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
    }

    @Test
    @XrayTest(key = "EIDOMNI-390", summary = "Successful deferred issuance and verification of a bound SD-JWT credential", description = """
            This test validates the end-to-end deferred issuance flow for a bound SD-JWT credential
            with selective disclosure requirements. The wallet retrieves the credential using a transaction ID
            and successfully constructs a presentation that satisfies the verifier's requirements.
            """)
    @Tag("uci_c1b")
    @Tag("uci_i1b")
    @Tag("ucv_o2a")
    @Tag("happy_path")
    void createDeferredBoundCredential_thenSuccess() {
        CredentialWithDeeplinkResponse response = issuerManager
                .createDeferredCredentialOffer("university_example_sd_jwt");

        WalletEntry entry = wallet.collectTransactionIdFromDeferredOffer(SwiyuApiVersionConfig.ID2,
                toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        issuerManager.updateState(response.getManagementId(), UpdateCredentialStatusRequestType.READY);

        var result = wallet.getCredentialFromTransactionId(entry);
        assertThat(result.get("credential")).isNotNull();

        var deepLink = verifierManager.verificationRequest()
                .acceptedIssuerDid(entry.getIssuerDid())
                .create();
        final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(deepLink);
        var res = entry.createPresentationForSdJwt(entry.getVerifiableCredential(), verificationDetails);

        wallet.respondToVerification(SwiyuApiVersionConfig.ID2, verificationDetails, res);
    }

    @Test
    @XrayTest(key = "EIDOMNI-409", summary = "Successful DCQL-based verification of a bound SD-JWT credential via OID4VP v2", description = """
            This test validates that a verifier can successfully perform DCQL-based verification of a bound
            SD-JWT credential through the OID4VP v2 endpoint. The wallet constructs a selective disclosure presentation
            that satisfies the DCQL query requirements.
            """)
    @Tag("uci_c1a")
    @Tag("uci_i1a")
    @Tag("ucv_o2a")
    @Tag("happy_path")
    void verifyDCQLRequest_thenSuccess() {
        CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("university_example_sd_jwt");

        WalletEntry entry = wallet.collectOffer(SwiyuApiVersionConfig.ID2, toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        var deepLink = verifierManager.verificationRequest()
                .acceptedIssuerDid(entry.getIssuerDid())
                .withUniversityDCQL()
                .create();

        final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(deepLink);
        var res = entry.createPresentationForSdJwt(entry.getVerifiableCredential(), verificationDetails);

        assert verificationDetails.getDcqlQuery() != null;
        wallet.respondToVerificationV1(verificationDetails, res);
    }

    @Test
    @XrayTest(key = "EIDOMNI-557", summary = "Successful DCQL-based batch verification of multiple SD-JWT credentials via OID4VP v1", description = """
            This test validates that a batch of multiple SD-JWT credentials can be successfully issued and verified
            using DCQL-based verification requests. Each credential in the batch is individually verified through
            separate OID4VP v1 verification flows.
            """)
    @Tag("uci_c1")
    @Tag("uci_i1")
    @Tag("ucv_o2")
    @Tag("happy_path")
    void verifyDCQLBatchIssuanceRequest_thenSuccess() {
        CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("university_example_sd_jwt");

        WalletBatchEntry entry = (WalletBatchEntry) wallet.collectOffer(SwiyuApiVersionConfig.V1,
                toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        for (int i = 0; i < entry.getIssuedCredentials().size(); i++) {
            var deepLink = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withDCQL()
                    .create();

            verifierManager.verifyState(VerificationStatus.PENDING);

            final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(deepLink);
            var res = entry.createPresentationForSdJwtIndex(i, verificationDetails);

            assert verificationDetails.getDcqlQuery() != null;
            wallet.respondToVerificationV1(verificationDetails, res);

            verifierManager.verifyState();
        }
    }

    @Test
    @XrayTest(key = "EIDOMNI-561", summary = "Verification rejection of an unbound credential when holder binding proof is required", description = """
            This test validates that a DCQL-based verification request requiring holder binding is correctly rejected
            when the wallet attempts to present an unbound credential. The verifier detects the missing holder key binding
            proof and rejects the presentation with an appropriate error.
            """)
    @Tag("ucv_o2")
    @Tag("edge_case")
    void verifyDCQLRequestHolderBindingWalletWithoutHolder_thenReject() {
        CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");

        WalletEntry entry = wallet.collectOffer(SwiyuApiVersionConfig.ID2, toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        var deepLink = verifierManager.verificationRequest()
                .acceptedIssuerDid(entry.getIssuerDid())
                .withUniversityDCQL()
                .create();

        final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(deepLink);
        var res = entry.getVerifiableCredential();

        assert verificationDetails.getDcqlQuery() != null;

        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
            wallet.respondToVerificationV1(verificationDetails, res);
        });
    }
}
