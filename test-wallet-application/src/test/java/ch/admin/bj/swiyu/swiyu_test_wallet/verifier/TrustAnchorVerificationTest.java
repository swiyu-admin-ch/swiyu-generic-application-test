package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.SdJwtSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

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
                    This test validates that a verifier successfully accepts a credential issued by a trusted issuer
                    when verified through a configured Trust Anchor. The verification succeeds for both SWIYU API versions
                    (OID4VP standard and DCQL-based), ensuring that trust relationships are properly validated.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1A)
    @Tag(ReportingTags.HAPPY_PATH)
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
                    This test ensures that verification fails when the issuer is not trusted through the provided
                    Trust Anchor. The test validates that trust anchor validation prevents accepting credentials from
                    untrusted issuers across both SWIYU API versions.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1B)
    @Tag(ReportingTags.EDGE_CASE)
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
            .as("Verification should fail for an issuer not trusted via the Trust Anchor")
            .isNotEqualTo(VerificationStatus.SUCCESS);
    }
}
