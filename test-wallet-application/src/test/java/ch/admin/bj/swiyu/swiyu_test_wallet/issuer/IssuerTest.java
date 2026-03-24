package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.IssuerMetadata;
import ch.admin.bj.swiyu.gen.issuer.model.OAuthAuthorizationServerMetadata;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.support.TestConstants;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.JsonConverter.toJsonNode;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class IssuerTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-387",
            summary = "Credential offer deeplink creation with SD-JWT content",
            description = """
                    This test validates that the Business Issuer correctly generates a credential offer deeplink for an SD-JWT
                    credential according to the OID4VCI specification. The deeplink contains all required parameters including a
                    unique pre-authorized code that differs from the management ID for security purposes.
                    """
    )
    @Tag(ReportingTags.UCI_C1)
    @Tag(ReportingTags.UCI_C1A)
    @Tag(ReportingTags.HAPPY_PATH)
    void offerDeepLinkWithSDJwt() {

        var credentialDetails = issuerManager.createCredentialOffer("bound_example_sd_jwt");
        var deeplink = toUri(credentialDetails.getOfferDeeplink());

        assertThat(deeplink.getScheme()).isEqualTo("swiyu");
        assertThat(deeplink.getQuery()).isNotNull();
        var credentialOfferQueryParam = PathSupport.splitQuery(deeplink).get("credential_offer");
        assertThat(credentialOfferQueryParam).isNotNull();

        var credentialOffer = toJsonNode(credentialOfferQueryParam);
        assertThat(credentialOffer.get("credential_issuer")).isNotNull();
        assertThat(credentialOffer.get("grants")).isNotNull();
        assertThat(credentialOffer.get("grants").get("urn:ietf:params:oauth:grant-type:pre-authorized_code")).isNotNull();
        assertThat(credentialOffer.get("grants").get("urn:ietf:params:oauth:grant-type:pre-authorized_code").get("pre-authorized_code")).isNotNull();
        var code = credentialOffer.at("/grants/urn:ietf:params:oauth:grant-type:pre-authorized_code/pre-authorized_code").asText();
        assert credentialDetails.getManagementId() != null;
        assertThat(code)
                .isNotNull()
                .isNotEmpty()
                .isNotEqualTo(credentialDetails.getManagementId().toString());
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-415",
            summary = "Issuer metadata endpoint validation",
            description = """
                    This test ensures that the issuer's OID4VCI metadata endpoint (.well-known/openid-credential-issuer)
                    correctly exposes compliant configuration data including issuer URI, display information, and all
                    supported credential configurations.
                    """
    )
    @Tag(ReportingTags.UCI_M1)
    @Tag(ReportingTags.UCI_M1A)
    @Tag(ReportingTags.HAPPY_PATH)
    void validateMetadata() {
        IssuerMetadata metadata = issuanceService.getWellKnownCredentialIssuerInfo();

        assertThat(metadata.getCredentialIssuer()).startsWith(TestConstants.ISSUER_URL);
        assertThat(metadata.getDisplay()).isNotNull();
        assertThat(metadata.getCredentialConfigurationsSupported()).isNotNull();
        assertThat(metadata.getCredentialConfigurationsSupported().get(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT)).isNotNull();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-391",
            summary = "OpenID configuration validation for OID4VCI issuer",
            description = """
                    This test validates that the issuer's OpenID configuration endpoint (.well-known/openid-configuration)
                    is correctly implemented for OID4VCI flows, confirming that issuer and token endpoint URLs match the
                    expected configuration pattern and are reachable.
                    """
    )
    @Tag(ReportingTags.UCI_W1)
    @Tag(ReportingTags.HAPPY_PATH)
    void validateConfiguration() {
        var openIdConfig = issuanceService.getWellKnownOpenIdConfiguration();

        assertThat(openIdConfig.getIssuer()).isNotNull();
        assertThat(openIdConfig.getIssuer()).startsWith(TestConstants.ISSUER_URL);
        assertThat(openIdConfig.getTokenEndpoint()).isNotNull();
        assertThat(openIdConfig.getTokenEndpoint()).isEqualTo("http://default-issuer-url.admin.ch/oid4vci/api/token");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-385",
            summary = "OAuth authorization server configuration validation for OID4VCI",
            description = """
                    This test validates that the OAuth authorization server endpoint exposed by the issuer is correctly
                    aligned with OID4VCI requirements, ensuring that authorization metadata and token endpoint URLs are
                    configured consistently with OID4VCI authorization flow expectations.
                    """
    )
    @Tag(ReportingTags.UCI_W1A)
    @Tag(ReportingTags.HAPPY_PATH)
    void validateOAuthAuthorizationServer() {
        OAuthAuthorizationServerMetadata openIdConfig = issuanceService.getWellKnownOAuthAuthorizationServer();

        assertThat(openIdConfig.getIssuer()).isNotNull();
        assertThat(openIdConfig.getIssuer()).startsWith(TestConstants.ISSUER_URL);
        assertThat(openIdConfig.getTokenEndpoint()).isNotNull();
        assertThat(openIdConfig.getTokenEndpoint()).isEqualTo("http://default-issuer-url.admin.ch/oid4vci/api/token");
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    @XrayTest(key = "EIDOMNI-620", summary = "Successful deferred issuance and verification of a bound SD-JWT credential when components require encryption", description = """
            This test validates the end-to-end deferred issuance flow for a bound SD-JWT credential
            with selective disclosure requirements. The wallet retrieves the credential using a transaction ID
            and successfully constructs a presentation that satisfies the verifier's requirements.
            The test runs for both SWIYU API versions (V1 and ID2) to ensure deferred credentials are correctly
            retrieved and their disclosures are properly validated.
            """)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "The fix for supported media type not available yet"
    )
    void payloadEncryptionCredentialIssuanceV1_withEncryptedPayload_thenSuccess(final boolean deferred) {
        // Given
        final Map<String, Object> temporarySubjectClaims = CredentialSubjectFixtures.mandatoryClaimsEmployeeProfile();
        final Map<String, Object> finalSubjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        CredentialWithDeeplinkResponse offer;
        if (deferred) {
            offer = issuerManager.createDeferredCredentialOffer(supportedMetadataId, temporarySubjectClaims);
        } else {
            offer = issuerManager.createCredentialOffer(supportedMetadataId, finalSubjectClaims);
        }

        wallet.setUseEncryption(true);
        WalletBatchEntry batchEntry;
        if (deferred) {
            batchEntry = wallet.collectTransactionIdFromDeferredOffer(toUri(offer.getOfferDeeplink()));
            // Then
            assertThat(batchEntry.getTransactionId()).isNotNull();

            // When
            issuerManager.updateCredentialForDeferredFlowRequestCreation(offer.getManagementId(), finalSubjectClaims);
            // Then
            issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.READY);

            // When
            wallet.getCredentialFromTransactionId(batchEntry);
        } else {
            // When
            batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        }
        // Then
        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(finalSubjectClaims);
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.ISSUED);
    }
}
