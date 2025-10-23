package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.junit.jupiter.api.*;
import org.assertj.core.api.AssertionsForClassTypes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.sql.*;


import java.util.List;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

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
class WalletTest {

    @Autowired
    IssuerImageConfig issuerImageConfig;
    @Autowired
    VerifierImageConfig verifierImageConfig;
    @Autowired
    IssuerConfig issuerConfig;
    @Autowired
    GenericContainer<?> issuerContainer;
    @Autowired
    GenericContainer<?> verifierContainer;
    @Autowired
    PostgreSQLContainer<?> dbTestContainer;
    @Autowired
    MockServerContainer mockServer;
    private Wallet wallet;
    private BusinessIssuer issuerManager;
    private VerifierManager verifierManager;
    private StatusList currentStatusList;

    /**
     * One-time setup: resolve dynamic container ports, configure helper facades, create status list
     * and instantiate wallet with resolved issuer & verifier contexts.
     */
    @BeforeAll
    void setup() {
        issuerConfig.setIssuerServiceUrl("http://%s:%s".formatted(issuerContainer.getHost(), issuerContainer.getMappedPort(8080)));
        issuerManager = new BusinessIssuer(issuerConfig);
        verifierManager = new VerifierManager(toUri("http://%s:%s".formatted(verifierContainer.getHost(), verifierContainer.getMappedPort(8080))).toString());
        currentStatusList = issuerManager.createStatusList(100000, 2);
        RestClient restClient = RestClient.builder().build();
        ServiceLocationContext issuerContext = new ServiceLocationContext(issuerContainer.getHost(), issuerContainer.getMappedPort(8080).toString());
        ServiceLocationContext verifierContext = new ServiceLocationContext(verifierContainer.getHost(), verifierContainer.getMappedPort(8080).toString());

        wallet = new Wallet(restClient, issuerContext, verifierContext);
    }

    @BeforeEach
    void beforeEach() {
        wallet.setEncryptionPreferred(false);
    }

    /**
     * Immediate issuance of an unbound credential followed by verification.
     * Flow: offer -> collect -> verification request -> respond with full SD-JWT -> verifier state check.
     */
    @Test
    void unboundNotDeferredCredential_thenSuccess() {
        CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");

        WalletEntry entry = wallet.collectOffer(toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        var deeplink = verifierManager.createVerificationRequest();

        RequestObject verificationRequest = wallet.getVerificationDetails(deeplink);

        wallet.respondToVerification(verificationRequest, entry.getVerifiableCredential());

        verifierManager.verifyState();
    }

    /**
     * Deferred issuance of an unbound credential.
     * Flow: deferred offer -> collect txn id -> issuer READY -> fetch credential -> verification.
     */
    @Test
    void unboundDeferredCredential_thenSuccess() {
        CredentialWithDeeplinkResponse response = issuerManager.createDeferredCredentialOffer("unbound_example_sd_jwt");

        WalletEntry entry = wallet.collectTransactionIdFromDeferredOffer(toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        issuerManager.updateState(response.getManagementId(), UpdateCredentialStatusRequestType.READY);

        var result = wallet.getCredentialFromTransactionId(entry);

        assertThat(result.get("credential")).isNotNull();

        var deepLink = verifierManager.createVerificationRequest();
        var verificationDetails = wallet.getVerificationDetails(deepLink);

        wallet.respondToVerification(verificationDetails, entry.getVerifiableCredential());
    }

    /**
     * Immediate issuance of a bound credential requiring a selective disclosure presentation.
     * Flow: offer -> collect -> verification request -> build presentation -> respond.
     */
    @Test
    void createBoundCredential_thenSuccess() {
        CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("university_example_sd_jwt");

        WalletEntry entry = wallet.collectOffer(toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        var deepLink = verifierManager.createVerificationRequest();
        var verificationDetails = wallet.getVerificationDetails(deepLink);
        var res = entry.createPresentationForSdJwt(entry.getVerifiableCredential(), verificationDetails);

        wallet.respondToVerification(verificationDetails, res);
    }

    /**
     * Deferred issuance of a bound credential combining deferred retrieval and presentation construction.
     */
    @Test
    void createDeferredBoundCredential_thenSuccess() {
        CredentialWithDeeplinkResponse response = issuerManager.createDeferredCredentialOffer("university_example_sd_jwt");

        WalletEntry entry = wallet.collectTransactionIdFromDeferredOffer(toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        issuerManager.updateState(response.getManagementId(), UpdateCredentialStatusRequestType.READY);

        var result = wallet.getCredentialFromTransactionId(entry);
        assertThat(result.get("credential")).isNotNull();

        var deepLink = verifierManager.createVerificationRequest();
        var verificationDetails = wallet.getVerificationDetails(deepLink);
        var res = entry.createPresentationForSdJwt(entry.getVerifiableCredential(), verificationDetails);

        wallet.respondToVerification(verificationDetails, res);
    }

    /**
     * DCQL-based verification request. Verifier supplies a DCQL query specifying credential requirements; wallet
     * constructs a compliant presentation and responds via V2 endpoint variant. (Method name retains typos intentionally.)
     */
    @Test
    void verifiyDCQLReuqest_thenSuccess() {
        CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("university_example_sd_jwt");

        WalletEntry entry = wallet.collectOffer(toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        var deepLink = verifierManager.createDCQLVerificationRequest();

        var verificationDetails = wallet.getVerificationDetails(deepLink);
        var res = entry.createPresentationForSdJwt(entry.getVerifiableCredential(), verificationDetails);

        assert verificationDetails.getDcqlQuery() != null;
        wallet.respondToVerificationV2(verificationDetails, res, verificationDetails.getDcqlQuery().getCredentials().getFirst().getId());
    }

    @Test
    @Tag("issuer")
    @Tag("verifier")
    void payloadEncryptedIssuanceAndVerificationFlow_thenSuccess() {
        wallet.setEncryptionPreferred(true);

        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");

        final WalletEntry entry = wallet.collectOffer(toUri(response.getOfferDeeplink()));
        AssertionsForClassTypes.assertThat(entry.getCredentialOffer()).isNotNull();

        final String deeplink = verifierManager.createVerificationRequest(true);

        final RequestObject verificationRequest = wallet.getVerificationDetails(deeplink);

        wallet.respondToVerification(verificationRequest, entry.getVerifiableCredential());

        verifierManager.verifyState();
    }

}
