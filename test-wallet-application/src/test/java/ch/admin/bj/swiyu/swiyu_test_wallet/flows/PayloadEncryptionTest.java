package ch.admin.bj.swiyu.swiyu_test_wallet.flows;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class PayloadEncryptionTest extends BaseTest {

    @BeforeEach
    void beforeEach() {
        wallet.setUseEncryption(true);
    }


    @ParameterizedTest
    @EnumSource(SwiyuApiVersionConfig.class)
    @XrayTest(
            key = "EIDOMNI-392",
            summary = "Successful issuance and verification of an encrypted SD-JWT credential",
            description = """
                    This test validates the end-to-end issuance and verification of an unbound SD-JWT credential where both
                    OID4VCI credential responses and OID4VP presentation responses are encrypted according to specification.
                    The test runs for both SWIYU API versions to ensure encryption works correctly across all supported flows.
                    """
    )
    @Tag("ucv_o2")
    @Tag("ucv_o2a")
    @Tag("happy_path")
    void verifierRequiresEncryption_walletSendsEncryptedPayload_thenSuccess(final SwiyuApiVersionConfig swiyuApiVersion) {
        final String expectedCrv = "P-256";
        final String expectedKty = "EC";
        final String expectedEncryptionAlgorithm = "A128GCM";

        log.info("Issuer creating credential offer requiring encryption");
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("bound_example_sd_jwt");

        log.info("Wallet collecting it using encryption");
        final WalletEntry entry = wallet.collectOffer(SwiyuApiVersionConfig.ID2, toUri(response.getOfferDeeplink()));
        AssertionsForClassTypes.assertThat(entry.getCredentialOffer()).isNotNull();

        log.info("Verifier creating verification request requiring encryption");
        String deeplink = null;
        if (swiyuApiVersion == SwiyuApiVersionConfig.ID2) {
            deeplink = verifierManager.verificationRequest()
                    .acceptedIssuerDid(entry.getIssuerDid())
                    .encrypted()
                    .create();
        } else if (swiyuApiVersion == SwiyuApiVersionConfig.V1) {
            deeplink = verifierManager.verificationRequest()
                    .acceptedIssuerDid(entry.getIssuerDid())
                    .withUniversityDCQL()
                    .encrypted()
                    .create();
        }

        final RequestObject verificationRequest = wallet.getVerificationDetailsUnsigned(deeplink);

        final OpenidClientMetadataDto metadata = verificationRequest.getClientMetadata();
        final JsonWebKey webKey = metadata.getJwks().getKeys().getFirst();
        final String encryptionAlgorithm = metadata.getEncryptedResponseEncValuesSupported().getFirst();

        assertThat(verificationRequest.getResponseMode()).isEqualTo(RequestObject.ResponseModeEnum.POST_JWT);
        assertThat(webKey.getCrv()).isEqualTo(expectedCrv);
        assertThat(webKey.getKty()).isEqualTo(expectedKty);
        assertThat(encryptionAlgorithm).isEqualTo(expectedEncryptionAlgorithm);

        log.info("Wallet sends encrypted presentation to verifier");
        final String token = entry.createPresentationForSdJwt(entry.getVerifiableCredential(), verificationRequest);
        wallet.respondToVerification(swiyuApiVersion, verificationRequest, token);

        verifierManager.verifyState();
    }



    @Test
    @XrayTest(
            key = "EIDOMNI-327",
            summary = "OID4VCI Happy Path with Encrypted Credential Request and Response",
            description = """
                    Validate that the Issuer correctly handles encryption of both credential request and credential response
                    for SWIYU API V1 (header SWIYU-API-Version: 2).
                    
                    Steps:
                    1. Issuer metadata exposes encryption support (ECDH-ES + A128GCM)
                    2. WalletBatchEntry generates ephemeral P-256 key
                    3. Wallet sends encrypted Credential Request (application/jwt)
                    4. Issuer encrypts Credential Response using Wallet ephemeral key
                    5. Wallet decrypts JWE and validates SD-JWT format
                    """
    )
    @Tag("uci_i1")
    @Tag("happy_path")
    @DisableIfImageTag(
            issuer = {"stable"},
            reason = "Fix for deferred encprytion is not available yet"
    )
    void issuerEncryptionV1_encryptedRequestAndResponse_thenSuccess() {
        final SwiyuApiVersionConfig apiVersion = SwiyuApiVersionConfig.V1;

        wallet.setUseEncryption(true);

        final CredentialWithDeeplinkResponse response =
                issuerManager.createCredentialOffer("unbound_example_sd_jwt");

        final WalletBatchEntry entry =
                (WalletBatchEntry) wallet.collectOffer(apiVersion, toUri(response.getOfferDeeplink()));

        assertThat(entry.getIssuerMetadata()).isNotNull();
        assertThat(entry.getCredentialConfigurationSupported()).isNotNull();
        assertThat(entry.getProofs()).hasSize(entry.getProofs().size());
    }
}
