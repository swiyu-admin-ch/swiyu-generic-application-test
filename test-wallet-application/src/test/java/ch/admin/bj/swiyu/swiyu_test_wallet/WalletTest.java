package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialInfoResponse;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
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
/**
 * Integration tests for {@link Wallet} exercising end-to-end SD-JWT credential issuance (immediate & deferred),
 * selective disclosure presentation creation for bound credentials, and verification flows (standard & DCQL-based)
 * against containerized issuer and verifier services.
 *
 * Happy-path scenarios:
 * <ul>
 *   <li><b>unboundNotDeferredCredential_thenSuccess</b>: Immediate issuance & verification of an unbound credential.</li>
 *   <li><b>unboundDeferredCredential_thenSuccess</b>: Deferred issuance (transaction id) of an unbound credential.</li>
 *   <li><b>createBoundCredential_thenSuccess</b>: Immediate issuance of a bound credential with selective disclosure presentation.</li>
 *   <li><b>createDeferredBoundCredential_thenSuccess</b>: Deferred issuance of a bound credential.</li>
 *   <li><b>verifiyDCQLReuqest_thenSuccess</b>: DCQL-based verification using V2 response API (method name typos preserved).</li>
 * </ul>
 * Notes:
 * <ul>
 *   <li>A large status list (size 100000, bit length 2) is created once for revocation/status embedding.</li>
 *   <li>Bound credentials require constructing a derived presentation; unbound credentials can be sent as-is.</li>
 *   <li>Method name typos are retained to avoid breaking historical reports or tooling references.</li>
 * </ul>
 */
class WalletTest extends BaseTest {

    @BeforeEach
    void beforeEach() {
        wallet.setEncryptionPreferred(false);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-386",
            summary = "Successful verification of an unbound SD-JWT credential (non-deferred)",
            description = """
                    This test validates the end-to-end issuance and verification of an unbound SD-JWT credential
                    through immediate OID4VCI credential issuance and OID4VP-based verification. The wallet successfully
                    collects the non-deferred credential and presents it to a verifier for validation.
                    """
    )
    @Tag("uci_c1a")
    @Tag("uci_i1")
    @Tag("ucv_o2")
    @Tag("happy_path")
    void unboundNotDeferredCredential_thenSuccess() {
        CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");

        WalletEntry entry = wallet.collectOffer(SwiyuApiVersionConfig.ID2, toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        var deeplink = verifierManager.verificationRequest()
                .acceptedIssuerDid(entry.getIssuerDid())
                .create();

        RequestObject verificationRequest = wallet.getVerificationDetailsUnsigned(deeplink);

        wallet.respondToVerification(SwiyuApiVersionConfig.ID2, verificationRequest, entry.getVerifiableCredential());

        verifierManager.verifyState();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-389",
            summary = "Successful deferred issuance and verification of an unbound SD-JWT credential",
            description = """
                    This test validates the end-to-end deferred issuance flow for an unbound SD-JWT credential,
                    where the wallet retrieves a transaction ID during the initial offer collection phase and
                    collects the credential after the issuer marks it as READY. The credential is subsequently
                    verified through the OID4VP interface.
                    """
    )
    @Tag("uci_c1b")
    @Tag("uci_i1b")
    @Tag("ucv_o2")
    @Tag("happy_path")
    void unboundDeferredCredential_thenSuccess() {
        CredentialWithDeeplinkResponse response = issuerManager.createDeferredCredentialOffer("unbound_example_sd_jwt");

        WalletEntry entry = wallet.collectTransactionIdFromDeferredOffer(toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        CredentialInfoResponse cred = issuerManager.getCredentialById(response.getManagementId());

        Map<String, Object> credentialStatus = new HashMap<>();
        credentialStatus.put("average_grade", 4.0);
        credentialStatus.put("name", "Data Science");
        credentialStatus.put("type", "Bachelor of Science");
        issuerManager.updateCredentialForDeferredFlowRequestCreation(response.getManagementId(), credentialStatus);

        issuerManager.updateState(response.getManagementId(), UpdateCredentialStatusRequestType.READY);

        var result = wallet.getCredentialFromTransactionId(entry);

        assertThat(result.get("credential")).isNotNull();

        var deepLink = verifierManager.verificationRequest()
                .acceptedIssuerDid(entry.getIssuerDid())
                .create();
        ;
        final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(deepLink);

        wallet.respondToVerification(SwiyuApiVersionConfig.ID2, verificationDetails, entry.getVerifiableCredential());

        issuerManager.verifyStatus(response.getManagementId(), CredentialStatusType.ISSUED);

        Map<String, Object> retryCredentialStatus = new HashMap<>();
        retryCredentialStatus.put("average_grade", 4.2);
        retryCredentialStatus.put("name", "Business Administration");
        retryCredentialStatus.put("type", "Bachelor of Business Administration");
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> issuerManager.updateCredentialForDeferredFlowRequestCreation(response.getManagementId(), retryCredentialStatus)
        );

        Assertions.assertThat(errorCode(ex))
                .as("Invalid refresh tokens must be rejected")
                .isEqualTo(400);

        Assertions.assertThat(errorJson(ex))
                .containsEntry("error_description", "Bad Request");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-393",
            summary = "Successful issuance and verification of a bound SD-JWT credential with selective disclosure",
            description = """
                    This test validates the immediate issuance of a bound SD-JWT credential that requires selective
                    disclosure during verification. The wallet constructs a derived presentation based on the verifier's
                    requirements and the credential is successfully validated.
                    """
    )
    @Tag("uci_c1a")
    @Tag("uci_i1a")
    @Tag("ucv_o2a")
    @Tag("happy_path")
    void createBoundCredential_thenSuccess() throws InterruptedException {
        int before = awaitStableIssuerCallbacks();

        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("university_example_sd_jwt");

        final WalletEntry entry = wallet.collectOffer(SwiyuApiVersionConfig.ID2, toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        awaitNIssuerCallback(before, 2);

        final String deepLink = verifierManager.verificationRequest(false).acceptedIssuerDid(entry.getIssuerDid()).withUniversity().create();
        final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(deepLink);
        final String res = entry.createPresentationForSdJwt(entry.getVerifiableCredential(), verificationDetails);

        before = awaitStableVerifierCallbacks();

        wallet.respondToVerification(
                SwiyuApiVersionConfig.ID2,
                verificationDetails,
                res
        );

        awaitOneVerifierCallback(before);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-390",
            summary = "Successful deferred issuance and verification of a bound SD-JWT credential",
            description = """
                    This test validates the end-to-end deferred issuance flow for a bound SD-JWT credential
                    with selective disclosure requirements. The wallet retrieves the credential using a transaction ID
                    and successfully constructs a presentation that satisfies the verifier's requirements.
                    """
    )
    @Tag("uci_c1b")
    @Tag("uci_i1b")
    @Tag("ucv_o2a")
    @Tag("happy_path")
    void createDeferredBoundCredential_thenSuccess() {
        CredentialWithDeeplinkResponse response = issuerManager.createDeferredCredentialOffer("university_example_sd_jwt");

        WalletEntry entry = wallet.collectTransactionIdFromDeferredOffer(toUri(response.getOfferDeeplink()));
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
    @XrayTest(
            key = "EIDOMNI-409",
            summary = "Successful DCQL-based verification of a bound SD-JWT credential via OID4VP v2",
            description = """
                    This test validates that a verifier can successfully perform DCQL-based verification of a bound
                    SD-JWT credential through the OID4VP v2 endpoint. The wallet constructs a selective disclosure presentation
                    that satisfies the DCQL query requirements.
                    """
    )
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
    @XrayTest(
            key = "EIDOMNI-557",
            summary = "Successful DCQL-based batch verification of multiple SD-JWT credentials via OID4VP v1",
            description = """
                    This test validates that a batch of multiple SD-JWT credentials can be successfully issued and verified
                    using DCQL-based verification requests. Each credential in the batch is individually verified through
                    separate OID4VP v1 verification flows.
                    """
    )
    @Tag("uci_c1")
    @Tag("uci_i1")
    @Tag("ucv_o2")
    @Tag("happy_path")
    void verifyDCQLBatchIssuanceRequest_thenSuccess() {
        CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("university_example_sd_jwt");

        WalletBatchEntry entry = (WalletBatchEntry) wallet.collectOffer(SwiyuApiVersionConfig.V1, toUri(response.getOfferDeeplink()));
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
    @XrayTest(
            key = "EIDOMNI-561",
            summary = "Verification rejection of an unbound credential when holder binding proof is required",
            description = """
                    This test validates that a DCQL-based verification request requiring holder binding is correctly rejected
                    when the wallet attempts to present an unbound credential. The verifier detects the missing holder key binding
                    proof and rejects the presentation with an appropriate error.
                    """
    )
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
