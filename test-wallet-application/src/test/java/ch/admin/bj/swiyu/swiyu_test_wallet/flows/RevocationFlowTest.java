package ch.admin.bj.swiyu.swiyu_test_wallet.flows;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@Slf4j
public class RevocationFlowTest extends BaseTest {

    @Test
    @XrayTest(
            key = "@TODO",
            summary = "Revoked credential cannot be verified in OID4VP flow",
            description = """
                    This test validates that a revoked credential cannot be used in an OID4VP verification flow.
                    After issuing a batch of credentials and subsequently revoking them, the verifier correctly rejects
                    the presentation with a credential_revoked error, preventing verification from succeeding.
                    """)
    @Tag("@TODO")
    void revokedCredential_whenVerified_thenFailureWithRevokedError() throws InterruptedException {
        // Given
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;

        // When - Issue credential
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId,
                subjectClaims);
        final WalletBatchEntry batchEntry = (WalletBatchEntry) wallet.collectOffer(SwiyuApiVersionConfig.V1, toUri(offer.getOfferDeeplink()));

        // Then - Verify credential was issued with correct claims
        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);

        // When - Revoke the credential
        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.REVOKED);

        // Then - The verification failed as the credential is revoked
        for (int i = 0; i < CredentialConfigurationFixtures.BATCH_SIZE; i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(true)
                    .createManagementResponse();
            final RequestObject verificationDetails = wallet
                    .getVerificationDetailsUnsigned(toUri(verification.getVerificationDeeplink()));
            verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

            final String presentation = batchEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
                wallet.respondToVerification(SwiyuApiVersionConfig.V1, verificationDetails, presentation);
            });

            ApiErrorAssert.assertThat(ex)
                    .hasError("invalid_transaction_data")
                    .hasErrorDescription("Credential has been Revoked!")
                    .hasDetail("credential_revoked")
                    .hasErrorCode("credential_revoked");

            verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
        }
    }

    @Test
    @XrayTest(
            key = "@TODO",
            summary = "Suspended credential cannot be verified but can be revalidated in OID4VP flow",
            description = """
                    This test validates the suspension and revalidation lifecycle of a credential in an OID4VP flow.
                    After issuing a batch of credentials, the issuer suspends them, causing verification to fail with 
                    a credential_suspended error. The issuer then revalidates the credentials by setting them back to ISSUED,
                    allowing subsequent verification attempts to succeed.
                    """)
    @Tag("@TODO")
    void suspendedCredential_whenSuspendedAndVerified_thenFailure_whenReissuedThenSuccess() throws InterruptedException {
        // Given
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.UNBOUND_EXAMPLE_SD_JWT;

        // When - Issue credential
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId,
                subjectClaims);
        final WalletBatchEntry batchEntry = (WalletBatchEntry) wallet.collectOffer(SwiyuApiVersionConfig.V1, toUri(offer.getOfferDeeplink()));

        // Then - Verify credential was issued with correct claims
        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);

        // When - Suspend the credential
        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.SUSPENDED);

        // Then - The verification fails as the credential is suspended
        for (int i = 0; i < CredentialConfigurationFixtures.BATCH_SIZE; i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(false)
                    .createManagementResponse();
            final RequestObject verificationDetails = wallet
                    .getVerificationDetailsUnsigned(toUri(verification.getVerificationDeeplink()));
            verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

            final int index = i;
            final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
                wallet.respondToVerification(SwiyuApiVersionConfig.V1, verificationDetails, batchEntry.getVerifiableCredential(index));
            });

            ApiErrorAssert.assertThat(ex)
                    .hasError("invalid_transaction_data")
                    .hasErrorDescription("Credential has been Suspended!")
                    .hasDetail("credential_suspended")
                    .hasErrorCode("credential_suspended");

            verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
        }

        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.ISSUED);

        // Then - The verification process succeed as the credential is valid again
        for (int i = 0; i < CredentialConfigurationFixtures.BATCH_SIZE; i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(false)
                    .createManagementResponse();
            final RequestObject verificationDetails = wallet
                    .getVerificationDetailsUnsigned(toUri(verification.getVerificationDeeplink()));
            verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

            wallet.respondToVerification(SwiyuApiVersionConfig.V1, verificationDetails,
                    batchEntry.getVerifiableCredential(i));

            verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
        }
    }
}
