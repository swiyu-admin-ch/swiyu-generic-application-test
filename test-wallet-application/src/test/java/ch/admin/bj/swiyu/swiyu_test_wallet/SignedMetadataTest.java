package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.net.URI;
import java.net.URL;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class SignedMetadataTest {

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

    @Test
    @Tag("issuer")
    @Tag("signed-metadata")
    @XrayTest(
            key = "EIDOMNI-402",
            summary = "Validate retrieval and verification of signed issuer metadata (happy path)",
            description = """
            This test validates that a wallet can successfully request, retrieve, and verify signed issuer metadata 
            according to the OID4VCI specification.

            Components:
            - Issuer: exposes the signed metadata endpoint.
            - Wallet: retrieves and validates the signed metadata.

            Preconditions:
            - Signed metadata feature is enabled on the issuer (ENABLE_SIGNED_METADATA=true).

            Test Flow:
            1. The wallet requests issuer metadata with Accept: application/jwt.
            2. The issuer returns a signed JWT (header.payload.signature).
            3. The wallet decodes the JWT, extracts metadata claims, and validates its structure.
            4. The wallet confirms the metadata signature and verifies required claims.
            5. The retrieved metadata is valid and contains expected OID4VCI fields.
            """
    )
    void shouldSuccessfullyValidateSignedMetadata() {
        var walletEntry = wallet.createWalletEntry();
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final String deeplink = response.getOfferDeeplink();

        walletEntry.receiveDeepLinkAndValidateIt(URI.create(deeplink));

        walletEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(walletEntry));
        walletEntry.setToken(wallet.collectToken(walletEntry));

        final IssuerMetadata metadata = wallet.getIssuerWellKnownMetadataSigned(walletEntry);

        assertThat(metadata).isNotNull();
    }
}
