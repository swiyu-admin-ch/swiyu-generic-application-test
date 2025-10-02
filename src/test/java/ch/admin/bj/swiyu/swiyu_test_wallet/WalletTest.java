package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.gen.issuer.model.CredentialOfferMetadataDto;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialOfferRequest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.CreateVerificationManagement;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.CredentialOffer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import ch.admin.bj.swiyu.swiyu_test_wallet.testcontainer.DBContainer;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;

import java.util.List;

import static ch.admin.bj.swiyu.swiyu_test_wallet.testcontainer.IssuerContainer.getIssuerContainer;
import static ch.admin.bj.swiyu.swiyu_test_wallet.testcontainer.MockServerContainer.getMockServer;
import static ch.admin.bj.swiyu.swiyu_test_wallet.testcontainer.VerifierContainer.startVerifierContainer;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.createDefaultRequest;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class WalletTest extends BaseTest {

    private final Network network = Network.newNetwork();
    private Wallet wallet;

    @Container
    PostgreSQLContainer<?> dbContainer = DBContainer.startupDbContainer(network);

    @Container
    GenericContainer<?> mockServer = getMockServer(network);

    @Container
    GenericContainer<?> issuerContainer = getIssuerContainer(network, dbContainer);

    @Container
    GenericContainer<?> verifierContainer = startVerifierContainer(network, dbContainer, mockServer);

    private BusinessIssuer issuerManager;
    private VerifierManager verifierManager;
    private StatusList statusList;

    @BeforeEach
    void setup() {
        IssuerConfig issuerConfig = new IssuerConfig();
        issuerConfig.setIssuerServiceUrl(toUri("http://%s:%s".formatted(issuerContainer.getHost(), issuerContainer.getMappedPort(8080))).toString());
        issuerManager = new BusinessIssuer(issuerConfig);
        verifierManager = new VerifierManager( toUri("http://%s:%s".formatted(verifierContainer.getHost(), verifierContainer.getMappedPort(8080))).toString());
        statusList = issuerManager.createStatusList(100000, 2);
        RestClient restClient = RestClient.builder().build();
        IssuerContext issuerContext = new IssuerContext(issuerContainer.getHost(), issuerContainer.getMappedPort(8080).toString());
        VerifierContext verifierContext = new VerifierContext(verifierContainer.getHost(), verifierContainer.getMappedPort(8080).toString());
        wallet = new Wallet(restClient, issuerContext, verifierContext);
    }

    @Test
    void unboundNotDeferredCredential_thenSuccess() {
        CredentialWithDeeplinkResponse response = createOffer(false, "unbound_example_sd_jwt");

        WalletEntry entry = wallet.collectOffer(toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        CreateVerificationManagement request = createDefaultRequest(false);

        ManagementResponse managementResponse = verifierManager.createVerificationRequest(request);

        RequestObject verificationRequest = wallet.getVerificationDetails(managementResponse.getVerificationDeeplink());

        wallet.respondToVerification(verificationRequest, entry.getVerifiableCredential());
    }

    @Test
    void unboundDeferredCredential_thenSuccess() {
        CredentialWithDeeplinkResponse response = createOffer(true, "unbound_example_sd_jwt");

        WalletEntry entry = wallet.collectTransactionIdFromDeferredOffer(toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        issuerManager.updateState(response.getManagementId(), UpdateCredentialStatusRequestType.READY);

        var result = wallet.getCredentialFromTransactionId(entry);

        assertThat(result.get("credential")).isNotNull();

        CreateVerificationManagement request = createDefaultRequest(false);

        ManagementResponse managementResponse = verifierManager.createVerificationRequest(request);

        var deepLink = managementResponse.getVerificationDeeplink();

        var verificationDetails = wallet.getVerificationDetails(deepLink);

        wallet.respondToVerification(verificationDetails, entry.getVerifiableCredential());
    }

    @Test
    void createBoundCredential_thenSuccess() {
        CredentialWithDeeplinkResponse response = createOffer(false, "university_example_sd_jwt");

        WalletEntry entry = wallet.collectOffer(toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        CreateVerificationManagement request = createDefaultRequest(true);

        ManagementResponse managementResponse = verifierManager.createVerificationRequest(request);

        var deepLink = managementResponse.getVerificationDeeplink();

        var verificationDetails = wallet.getVerificationDetails(deepLink);

        var res = entry.createPresentationForSdJwt(entry.getVerifiableCredential(), verificationDetails);

        wallet.respondToVerification(verificationDetails, res);
    }

    @Test
    void createDeferredBoundCredential_thenSuccess() {
        CredentialWithDeeplinkResponse response = createOffer(true, "university_example_sd_jwt");

        WalletEntry entry = wallet.collectTransactionIdFromDeferredOffer(toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        issuerManager.updateState(response.getManagementId(), UpdateCredentialStatusRequestType.READY);

        var result = wallet.getCredentialFromTransactionId(entry);
        assertThat(result.get("credential")).isNotNull();

        CreateVerificationManagement request = createDefaultRequest(true);

        ManagementResponse managementResponse = verifierManager.createVerificationRequest(request);

        var deepLink = managementResponse.getVerificationDeeplink();

        var verificationDetails = wallet.getVerificationDetails(deepLink);

        var res = entry.createPresentationForSdJwt(entry.getVerifiableCredential(), verificationDetails);

        wallet.respondToVerification(verificationDetails, res);
    }

    private CredentialWithDeeplinkResponse createOffer(boolean deferred, String supportedMetadataId) {
        CredentialOfferMetadataDto credentialOfferMetadataDto = new CredentialOfferMetadataDto();
        credentialOfferMetadataDto.setDeferred(deferred);

        CredentialOfferRequest offer = new CredentialOfferRequest();
        offer.setCredentialSubjectData(CredentialOffer.defaultSubjectData());
        offer.setStatusLists(List.of(statusList.getStatusRegistryUrl()));
        offer.setCredentialMetadata(credentialOfferMetadataDto);
        offer.setMetadataCredentialSupportedId(List.of(supportedMetadataId));
        offer.setOfferValiditySeconds(86400); // 24h

        return issuerManager.createCredential(offer);
    }
}
