package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.verifier.model.*;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.SdJwtSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
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

    @ParameterizedTest(name = "Successful verification through a valid Trust Anchor – SWIYU API v{0}")
    @CsvSource({"1", "2"})
    @Tag("verifier")
    @Tag("trust-anchor")
    @XrayTest(
            key = "EIDOMNI-195",
            summary = "Successful verification through a valid Trust Anchor",
            description = """
            This parameterized test validates that a verifier successfully accepts a credential 
            issued by a trusted issuer when verified via a configured Trust Anchor.
            
            It runs for both SWIYU API versions:
             - Version 1: standard verification (OID4VP)
             - Version 2: DCQL-based verification (OID4VP v2)
             
            Steps:
            1. Configure a Trust Anchor linked to the credential issuer.
            2. Issue a credential from this trusted issuer.
            3. Create a verification request using the chosen SWIYU API version.
            4. Present the credential through the wallet.
            5. Verify that the verification succeeds (state == SUCCESS).
            """
    )
    void verificationWithValidTrustAnchor_thenSuccess(final int swiyuApiVersion) {
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final WalletEntry entry = wallet.collectOffer(toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        final String did = SdJwtSupport.extractIssuer(entry.getIssuerSdJwt());

        CreateVerificationManagement request = null;
        if (swiyuApiVersion == 1) {
            request = verifierManager.createVerificationRequestObject();
        } else if (swiyuApiVersion == 2) {
            request = verifierManager.createDCQLVerificationRequestObject();
        } else {
            throw new IllegalStateException("Invalid swiyu api version");
        }
        final TrustAnchor anchor = new TrustAnchor()
                .did(did)
                .trustRegistryUri("trust-reg.trust-infra.swiyu-int.admin.ch");
        request.addTrustAnchorsItem(anchor);

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

    @ParameterizedTest(name = "Verification rejected when issuer not trusted via Trust Anchor – SWIYU API v{0}")
    @CsvSource({"1", "2"})
    @Tag("verifier")
    @Tag("trust-anchor")
    @XrayTest(
            key = "EIDOMNI-397",
            summary = "Verification rejected when issuer not trusted via Trust Anchor",
            description = """
            This test ensures that a DCQL-based verification request fails when the issuer
            is not trusted through the provided Trust Anchor.

            Steps:
            1. Configure a Trust Anchor that has no trust statement linking to the issuer.
            2. Issue a credential from an untrusted issuer.
            3. Create a DCQL verification request referencing the untrusted Trust Anchor.
            4. Present the credential through the wallet.
            5. Verify that the process fails with an 'issuer_not_accepted' or equivalent error.
            """
    )
    void verificationWithUntrustedIssuer_thenFails(final int swiyuApiVersion) {
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final WalletEntry entry = wallet.collectOffer(toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        final String did = SdJwtSupport.extractIssuer(entry.getIssuerSdJwt());

        CreateVerificationManagement request = null;
        if (swiyuApiVersion == 1) {
            request = verifierManager.createVerificationRequestObject();
        } else if (swiyuApiVersion == 2) {
            request = verifierManager.createDCQLVerificationRequestObject();
        } else {
            throw new IllegalStateException("Invalid swiyu api version");
        }
        final TrustAnchor anchor = new TrustAnchor()
                .did(did)
                .trustRegistryUri("fake-reg.trust-infra.swiyu-int.admin.ch");
        request.addTrustAnchorsItem(anchor);

        final ManagementResponse managementResponse = verifierManager.createVerificationRequest(request);
        assertThat(managementResponse).isNotNull();
        assertThat(managementResponse.getVerificationDeeplink()).isNotBlank();

        var verificationRequest = wallet.getVerificationDetails(managementResponse.getVerificationDeeplink());
        wallet.respondToVerification(verificationRequest, entry.getVerifiableCredential());

        final ManagementResponse result = verifierManager.verifyState();

        assertThat(result.getState())
                .isNotEqualTo(VerificationStatus.SUCCESS)
                .as("Verification should fail for an issuer not trusted via the Trust Anchor");
    }
}
