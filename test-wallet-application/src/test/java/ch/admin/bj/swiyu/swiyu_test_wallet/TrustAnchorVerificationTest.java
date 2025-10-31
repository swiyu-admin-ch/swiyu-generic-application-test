package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.verifier.model.*;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class TrustAnchorVerificationTest {

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

    private BusinessIssuer issuerManager;
    private VerifierManager verifierManager;
    private Wallet wallet;

    @BeforeAll
    void setup() {
        final String issuerUrl = "http://%s:%s".formatted(issuerContainer.getHost(), issuerContainer.getMappedPort(8080));
        final String verifierUrl = "http://%s:%s".formatted(verifierContainer.getHost(), verifierContainer.getMappedPort(8080));

        issuerConfig.setIssuerServiceUrl(issuerUrl);

        issuerManager = new BusinessIssuer(issuerConfig);
        verifierManager = new VerifierManager(verifierUrl);

        wallet = new Wallet(org.springframework.web.client.RestClient.builder().build(),
                new ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext(issuerContainer.getHost(), issuerContainer.getMappedPort(8080).toString()),
                new ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext(verifierContainer.getHost(), verifierContainer.getMappedPort(8080).toString()));

        issuerManager.createStatusList(10000, 2);
    }

    @Test
    @Tag("verifier")
    @Tag("trust-anchor")
    @XrayTest(
            key = "EID-3001",
            summary = "Verifier accepts credential trusted via Trust Anchor",
            description = """
                Validate that a verifier accepts a credential issued by an issuer 
                trusted through a configured Trust Anchor.

                Steps:
                1. Configure a Trust Anchor with a valid trust statement linking to the issuer.
                2. Issue a credential from the trusted issuer.
                3. Create a verification request using the Trust Anchor.
                4. Present the credential through the wallet.
                5. Verify that the process completes successfully.
                """
    )
    void verificationWithValidTrustAnchor_thenSuccess() {
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final WalletEntry entry = wallet.collectOffer(toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        final TrustAnchor anchor = new TrustAnchor()
                .did("did:example:root")
                .trustRegistryUri("https://trust-reg.trust-infra.swiyu-int.admin.ch");

        final CreateVerificationManagement request = new CreateVerificationManagement()
                .trustAnchors(List.of(anchor))
                .jwtSecuredAuthorizationRequest(false);

        final ManagementResponse managementResponse = verifierManager.createVerificationRequest(request);
        assertThat(managementResponse).isNotNull();
        assertThat(managementResponse.getVerificationDeeplink()).isNotBlank();

        var verificationRequest = wallet.getVerificationDetails(managementResponse.getVerificationDeeplink());
        wallet.respondToVerification(verificationRequest, entry.getVerifiableCredential());

        final ManagementResponse result = verifierManager.verifyState();

        assertThat(result.getState()).isEqualTo(VerificationStatus.SUCCESS);
        assertThat(result.getId()).isNotNull();
        assertThat(result.getPresentationDefinition()).isNotNull();
    }

    @Test
    @Tag("verifier")
    @Tag("trust-anchor")
    @XrayTest(
            key = "EID-3002",
            summary = "Verifier rejects credential not trusted via Trust Anchor",
            description = """
                Ensure that a verifier rejects a credential from an issuer 
                not included in the Trust Anchor’s trust chain.

                Steps:
                1. Configure a Trust Anchor without any trust statement for the issuer.
                2. Issue a credential from an untrusted issuer.
                3. Create a verification request referencing the Trust Anchor.
                4. Present the credential through the wallet.
                5. Verify that the process fails with 'issuer_not_accepted'.
                """
    )
    void verificationWithUntrustedIssuer_thenFails() {
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final WalletEntry entry = wallet.collectOffer(toUri(response.getOfferDeeplink()));

        final TrustAnchor anchor = new TrustAnchor()
                .did("did:example:root")
                .trustRegistryUri("https://trust-reg.trust-infra.swiyu-int.admin.ch");

        final CreateVerificationManagement request = new CreateVerificationManagement()
                .trustAnchors(List.of(anchor))
                .jwtSecuredAuthorizationRequest(false);

        final ManagementResponse managementResponse = verifierManager.createVerificationRequest(request);
        var verificationRequest = wallet.getVerificationDetails(managementResponse.getVerificationDeeplink());

        wallet.respondToVerification(verificationRequest, entry.getVerifiableCredential());

        final ManagementResponse result = verifierManager.createVerificationRequest(request); // requery
        assertThat(result.getState()).isNotEqualTo(VerificationStatus.SUCCESS);
    }
}
