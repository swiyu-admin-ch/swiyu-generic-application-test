package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_response.CredentialResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_response.CredentialResponseAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class DeferredFlowTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-667",
            summary = "Deferred credential issuance respects specification with 202 pending status in V1 API",
            description = """
                    This test validates that deferred credential requests conform to the specification in V1 API mode.
                    The wallet receives a 202 status and transaction ID when requesting a deferred credential, maintaining the 202 status until the issuer marks the credential as ready.
                    Once the issuer transitions the credential state to READY, the wallet can successfully retrieve the issued credential batch.
                    This ensures specification-compliant deferred issuance flow behavior.
                    """
    )
    @Tag("uci_i1")
    @Tag("edge_case")
    @DisableIfImageTag(
            issuer = {"stable", "rc", "staging"},
            reason = "The images have not the fix yet (Spec about 202 if credential deferred not available)."
    )
    @Deprecated(forRemoval = true)
    void deferredCredentialRequestV1_whenCredentialNotReady_remainsDeferred() throws InterruptedException {
        // Given
        final SwiyuApiVersionConfig apiVersion = SwiyuApiVersionConfig.V1;
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.mandatoryClaimsEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createDeferredCredentialOffer(
                supportedMetadataId,
                subjectClaims);
        final WalletBatchEntry batchEntry = (WalletBatchEntry) wallet.collectTransactionIdFromDeferredOffer(apiVersion, toUri(offer.getOfferDeeplink()));
        // Then
        assertThat(batchEntry.getTransactionId()).isNotNull();
        CredentialResponseAssert.assertThat(batchEntry.getCredentialResponse()).hasCode(202);
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.DEFERRED);

        // When
        final CredentialResponse credentialResponse = wallet.getCredentialFromTransactionId(apiVersion, batchEntry);

        // Then
        CredentialResponseAssert.assertThat(credentialResponse)
                .hasTransactionId()
                .hasInterval()
                .hasCode(202);

        // When
        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.READY);
        wallet.getCredentialFromTransactionId(apiVersion, batchEntry);

        // Then
        CredentialResponseAssert.assertThat(credentialResponse)
                .hasTransactionId()
                .hasInterval()
                .hasCode(202);
        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-668",
            summary = "Deferred credential issuance returns immediate error for backward compatibility in deprecated ID2 API",
            description = """
                    This test validates the non-specification-compliant behavior of the ID2 API mode for backward compatibility purposes.
                    The wallet receives a 400 error with ISSUANCE_PENDING status when requesting a deferred credential, rather than the 202 accepted response.
                    This deprecated behavior prioritizes backward compatibility with legacy systems over specification compliance.
                    The test confirms this legacy behavior is maintained during the deprecation period.
                    """
    )
    @Tag("uci_i1")
    @Tag("edge_case")
    @Deprecated(forRemoval = true)
    void deferredCredentialRequestID2_whenCredentialNotReady_remainsDeferred() throws InterruptedException {
        // Given
        final SwiyuApiVersionConfig apiVersion = SwiyuApiVersionConfig.ID2;
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.mandatoryClaimsEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createDeferredCredentialOffer(
                supportedMetadataId,
                subjectClaims);
        final WalletEntry entry = wallet.collectTransactionIdFromDeferredOffer(apiVersion, toUri(offer.getOfferDeeplink()));
        // Then
        assertThat(entry.getTransactionId()).isNotNull();
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.DEFERRED);

        // When
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class,
                () -> wallet.getCredentialFromTransactionId(apiVersion, entry));

        // Then
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasError("ISSUANCE_PENDING")
                .hasErrorDescription("The credential is not marked as ready to be issued");
    }
}
