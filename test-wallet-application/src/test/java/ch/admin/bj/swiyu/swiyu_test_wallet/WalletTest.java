package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@Testcontainers
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import({CompleteEnvironmentTestConfiguration.class, ExternalEnvironmentTestConfiguration.class})
class WalletTest {

    @Autowired
    IssuerImageConfig issuerImageConfig;
    @Autowired
    VerifierImageConfig verifierImageConfig;
    @Autowired
    IssuerConfig issuerConfig;
    @Autowired(required = false)
    GenericContainer<?> issuerContainer;
    @Autowired(required = false)
    GenericContainer<?> verifierContainer;
    @Autowired
    PostgreSQLContainer<?> dbTestContainer;
    @Autowired
    MockServerContainer mockServer;
    private Wallet wallet;
    private BusinessIssuer issuerManager;
    private VerifierManager verifierManager;

    @Value("${ISSUER_HOST:localhost}")
    String issuerHostEnv;
    @Value("${ISSUER_PORT:8081}")
    int issuerPortEnv;
    @Value("${VERIFIER_HOST:localhost}")
    String verifierHostEnv;
    @Value("${VERIFIER_PORT:8082}")
    int verifierPortEnv;

    @BeforeEach
    void setup() {
        String issuerHost;
        int issuerPort;
        String verifierHost;
        int verifierPort;
        if (issuerContainer != null && verifierContainer != null) {
            issuerHost = issuerContainer.getHost();
            issuerPort = issuerContainer.getMappedPort(8080);
            verifierHost = verifierContainer.getHost();
            verifierPort = verifierContainer.getMappedPort(8080);
        } else {
            issuerHost = issuerHostEnv;
            issuerPort = issuerPortEnv;
            verifierHost = verifierHostEnv;
            verifierPort = verifierPortEnv;
        }
        issuerConfig.setIssuerServiceUrl(toUri("http://%s:%s".formatted(issuerHost, issuerPort)).toString());
        issuerManager = new BusinessIssuer(issuerConfig);
        verifierManager = new VerifierManager(toUri("http://%s:%s".formatted(verifierHost, verifierPort)).toString());
        issuerManager.createStatusList(100000, 2);
        RestClient restClient = RestClient.builder().build();
        ServiceLocationContext issuerContext = new ServiceLocationContext(issuerHost, Integer.toString(issuerPort));
        ServiceLocationContext verifierContext = new ServiceLocationContext(verifierHost, Integer.toString(verifierPort));

        wallet = new Wallet(restClient, issuerContext, verifierContext);
    }

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
}
