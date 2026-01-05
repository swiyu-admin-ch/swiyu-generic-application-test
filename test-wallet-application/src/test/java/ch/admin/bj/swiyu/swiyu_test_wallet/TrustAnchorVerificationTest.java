package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.SdJwtSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.runner.Request;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class TrustAnchorVerificationTest extends BaseTest {

    @ParameterizedTest(name = "Successful verification through a valid Trust Anchor – SWIYU API v{0}")
    @EnumSource(SwiyuApiVersionConfig.class)
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
    @Tag("ucv_o1")
    @Tag("happy_path")
    @Disabled("No business mock")
    void verificationWithValidTrustAnchor_thenSuccess(final SwiyuApiVersionConfig swiyuApiVersion) {
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final WalletEntry entry = wallet.collectOffer(SwiyuApiVersionConfig.ID2, toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        final String did = SdJwtSupport.extractIssuer(entry.getIssuerSdJwt());

        final TrustAnchor anchor = new TrustAnchor()
                .did(did)
                .trustRegistryUri("trust-reg.trust-infra.swiyu-int.admin.ch");
        String deeplink = null;
        if (swiyuApiVersion == SwiyuApiVersionConfig.ID2) {
            deeplink = verifierManager.verificationRequest()
                    .trustAnchor(anchor)
                    .create();
        } else if (swiyuApiVersion == SwiyuApiVersionConfig.V1) {
            deeplink = verifierManager.verificationRequest()
                    .trustAnchor(anchor)
                    .withDCQL()
                    .create();
        }

        final RequestObject verificationRequest = wallet.getVerificationDetailsUnsigned(deeplink);
        wallet.respondToVerification(SwiyuApiVersionConfig.ID2, verificationRequest, entry.getVerifiableCredential());

        final ManagementResponse result = verifierManager.verifyState();

        assertThat(result.getState()).isEqualTo(VerificationStatus.SUCCESS);
        assertThat(result.getId()).isNotNull();
        assertThat(result.getPresentationDefinition()).isNotNull();
    }

    @ParameterizedTest(name = "Verification rejected when issuer not trusted via Trust Anchor – SWIYU API v{0}")
    @EnumSource(SwiyuApiVersionConfig.class)
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
    @Tag("ucv_o1")
    @Tag("edge_case")
    @Disabled("No business trust mock")
    void verificationWithUntrustedIssuer_thenFails(final SwiyuApiVersionConfig swiyuApiVersion) {
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final WalletEntry entry = wallet.collectOffer(SwiyuApiVersionConfig.ID2, toUri(response.getOfferDeeplink()));
        assertThat(entry.getCredentialOffer()).isNotNull();

        final String did = SdJwtSupport.extractIssuer(entry.getIssuerSdJwt());

        final TrustAnchor anchor = new TrustAnchor()
                .did(did)
                .trustRegistryUri("fake-reg.trust-infra.swiyu-int.admin.ch");
        String deeplink = null;
        if (swiyuApiVersion == SwiyuApiVersionConfig.ID2) {
            deeplink = verifierManager.verificationRequest()
                    .trustAnchor(anchor)
                    .create();
        } else if (swiyuApiVersion == SwiyuApiVersionConfig.V1) {
            deeplink = verifierManager.verificationRequest()
                    .trustAnchor(anchor)
                    .withDCQL()
                    .create();
        }

        final RequestObject verificationRequest = wallet.getVerificationDetailsUnsigned(deeplink);
        wallet.respondToVerification(SwiyuApiVersionConfig.ID2, verificationRequest, entry.getVerifiableCredential());

        final ManagementResponse result = verifierManager.verifyState();

        assertThat(result.getState())
                .isNotEqualTo(VerificationStatus.SUCCESS)
                .as("Verification should fail for an issuer not trusted via the Trust Anchor");
    }
}
