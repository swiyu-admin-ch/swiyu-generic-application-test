package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
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
import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;

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

    @Test
    @XrayTest(
            key = "EIDOMNI-386",
            summary = "Successful verification of an unbound SD-JWT credential (non-deferred)",
            description = """
                    This test validates the complete SD-JWT credential lifecycle where a verifier successfully
                    validates a non-deferred, unbound credential issued through the OID4VCI flow and presented
                    via the OID4VP interface.
                    
                    Steps:
                    1. The issuer creates a credential offer for an unbound SD-JWT credential (immediate issuance, non-deferred).
                    2. The wallet collects the offer through the deeplink and retrieves the SD-JWT credential.
                    3. The verifier generates a verification request according to the OID4VP flow.
                    4. The wallet obtains the verification request object and constructs a presentation containing the full SD-JWT.
                    5. The wallet submits the SD-JWT presentation back to the verifier.
                    6. The verifier processes the SD-JWT and confirms that the verification state is SUCCESS.
                    """
    )
    //@ComponentTest("issuer")
    //@ComponentTest("verifier")
    @Tag("issuance")
    @Tag("verification")
    void unboundNotDeferredCredential_thenSuccess() {
        CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");

        WalletEntry entry = wallet.collectOffer(toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        var deeplink = verifierManager.createVerificationRequest();

        RequestObject verificationRequest = wallet.getVerificationDetails(deeplink);

        wallet.respondToVerification(verificationRequest, entry.getVerifiableCredential());

        verifierManager.verifyState();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-389",
            summary = "Successful deferred issuance and verification of an unbound SD-JWT credential",
            description = """
                    This test validates that an unbound SD-JWT credential can be successfully issued using
                    the deferred OID4VCI flow and subsequently verified through the OID4VP interface.
                    
                    Steps:
                    1. The issuer creates a deferred credential offer for an unbound SD-JWT credential.
                    2. The wallet collects the transaction ID from the deferred offer deeplink.
                    3. The issuer updates the credential state to READY, making it available for retrieval.
                    4. The wallet fetches the issued SD-JWT credential using the transaction ID.
                    5. The verifier initiates a verification request following the OID4VP process.
                    6. The wallet retrieves verification details and constructs a presentation including the SD-JWT.
                    7. The wallet submits the SD-JWT presentation to the verifier.
                    8. The verifier successfully validates the SD-JWT and confirms the verification state as SUCCESS.
                    """
    )
    //@ComponentTest("issuer")
    //@ComponentTest("verifier")
    @Tag("issuance")
    @Tag("verification")
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

    @Test
    @XrayTest(
            key = "EIDOMNI-393",
            summary = "Successful issuance and verification of a bound SD-JWT credential with selective disclosure",
            description = """
                    This test validates the immediate issuance of a bound SD-JWT credential that requires a selective disclosure 
                    presentation during verification. It ensures that the credential bound to a holder's key can be successfully 
                    issued and verified through the OID4VCI and OID4VP flows.
                    
                    Steps:
                    1. The issuer creates a credential offer for a bound SD-JWT credential (e.g., university_example_sd_jwt).
                    2. The wallet collects the credential offer from the deeplink and retrieves the bound SD-JWT credential.
                    3. The verifier initiates a verification request based on the OID4VP protocol.
                    4. The wallet constructs a selective disclosure presentation using the SD-JWT and the verifier's request.
                    5. The wallet sends the selective disclosure presentation to the verifier.
                    6. The verifier validates the bound SD-JWT presentation and confirms that the verification state is SUCCESS.
                    """
    )
    //@ComponentTest("issuer")
    //@ComponentTest("verifier")
    @Tag("issuance")
    @Tag("verification")
    void createBoundCredential_thenSuccess() {
        CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("university_example_sd_jwt");

        WalletEntry entry = wallet.collectOffer(toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        var deepLink = verifierManager.createVerificationRequest();
        var verificationDetails = wallet.getVerificationDetails(deepLink);
        var res = entry.createPresentationForSdJwt(entry.getVerifiableCredential(), verificationDetails);

        wallet.respondToVerification(verificationDetails, res);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-390",
            summary = "Successful deferred issuance and verification of a bound SD-JWT credential",
            description = """
                    This test validates the end-to-end flow for deferred issuance of a bound SD-JWT credential, 
                    ensuring correct handling of deferred retrieval and subsequent selective disclosure presentation 
                    through the OID4VCI and OID4VP processes.
                    
                    Steps:
                    1. The issuer creates a deferred credential offer for a bound SD-JWT credential (e.g., university_example_sd_jwt).
                    2. The wallet collects the transaction ID from the deferred offer deeplink.
                    3. The issuer updates the credential status to READY, making the SD-JWT available for retrieval.
                    4. The wallet fetches the bound SD-JWT credential using the transaction ID.
                    5. The verifier initiates a verification request following the OID4VP flow.
                    6. The wallet retrieves verification details and constructs a selective disclosure presentation 
                       using the bound SD-JWT.
                    7. The wallet submits the presentation to the verifier.
                    8. The verifier validates the bound SD-JWT and confirms that the verification state is SUCCESS.
                    """
    )
    //@ComponentTest("issuer")
    //@ComponentTest("verifier")
    @Tag("issuance")
    @Tag("verification")
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

    @Test
    @XrayTest(
            key = "EIDOMNI-409",
            summary = "Successful DCQL-based verification of a bound SD-JWT credential via OID4VP v2",
            description = """
                    This test validates that a verifier can successfully perform a DCQL-based verification of a bound SD-JWT credential 
                    through the OID4VP v2 endpoint. The verifier supplies a Digital Credential Query Language (DCQL) request specifying 
                    credential requirements, and the wallet constructs a compliant SD-JWT presentation in response.
                    
                    Steps:
                    1. The issuer creates a credential offer for a bound SD-JWT credential (e.g., university_example_sd_jwt).
                    2. The wallet collects the credential offer via the deeplink and retrieves the issued SD-JWT credential.
                    3. The verifier generates a DCQL-based verification request defining the required credential attributes.
                    4. The wallet retrieves verification details, including the DCQL query structure.
                    5. The wallet builds a compliant selective disclosure presentation from the SD-JWT that satisfies the DCQL query.
                    6. The wallet responds to the verifier via the OID4VP v2 endpoint using the DCQL query context.
                    7. The verifier validates the presentation and confirms that the verification state is SUCCESS.
                    """
    )
    //@ComponentTest("issuer")
    //@ComponentTest("verifier")
    @Tag("issuance")
    @Tag("verification")
    @Tag("dcql")
    void verifyDCQLRequest_thenSuccess() {
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
    @XrayTest(
            key = "EIDOMNI-392",
            summary = "Successful issuance and verification of an encrypted SD-JWT credential",
            description = """
                    This test validates the end-to-end issuance and verification of an unbound SD-JWT credential 
                    where both issuance and presentation responses are encrypted according to OID4VCI and OID4VP 
                    encryption requirements.
                    
                    Steps:
                    1. The wallet indicates preference for encrypted responses (encryption_preferred = true).
                    2. The issuer creates a credential offer for an unbound SD-JWT credential.
                    3. The wallet collects the credential offer and retrieves the encrypted SD-JWT credential.
                    4. The verifier creates a verification request that requires encrypted presentations.
                    5. The wallet retrieves the verification request details.
                    6. The wallet constructs and sends an encrypted SD-JWT presentation back to the verifier.
                    7. The verifier decrypts and validates the presentation, confirming that the verification state is SUCCESS.
                    """
    )
    //@ComponentTest("issuer")
    //@ComponentTest("verifier")
    @Tag("issuance")
    @Tag("verification")
    @Tag("encryption")
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
