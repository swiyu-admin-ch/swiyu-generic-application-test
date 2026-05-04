package ch.admin.bj.swiyu.swiyu_test_wallet.flows;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class IssuanceKeyAttestationTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-893",
            summary = "Bound SD-JWT credential issuance succeeds when key attestation is valid",
            description = """
                    This test validates that a bound SD-JWT credential is successfully issued when the wallet
                    provides a key attestation JWT signed by a key that matches the attestation authority's
                    DID document. The issued credential is then verified by the verifier.
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.STAGING, ImageTags.RC},
            reason = "This feature is not available yet"
    )
    void boundNonDeferredCredential_whenKeyAttestationIsValid_thenSuccess() {
        // Given
        wallet.setMockAttestationAuthority(mockAttestationAuthority);
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.UNIVERSITY_EXAMPLE_ANY_KEY_ATTESTATION_REQUIRED_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId,
                subjectClaims);
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        // Then
        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);

        // When
        for (int i = 0; i < batchEntry.getIssuedCredentials().size(); i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL()
                    .createManagementResponse();
            final RequestObject verificationDetails = wallet
                    .getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
            verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
            final String presentation = batchEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            wallet.respondToVerification(verificationDetails, presentation);
            // Then
            verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-900",
            summary = "Bound SD-JWT credential issuance is rejected when key attestation signature is mismatched",
            description = """
                    This test validates that the issuer rejects a credential request when the key attestation JWT
                    is signed with a key that does not match the public key in the attestation authority's DID document.
                    The wallet must not receive any credential.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.STAGING, ImageTags.RC},
            reason = "This feature is not available yet"
    )
    void boundNonDeferredCredential_whenKeyAttestationSignatureIsMismatched_thenIssuanceRejected() {
        // Given
        wallet.setMockAttestationAuthority(mockAttestationAuthority.withMismatchedSigningKey());
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.UNIVERSITY_EXAMPLE_ANY_KEY_ATTESTATION_REQUIRED_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId, subjectClaims);

        // Then - the issuer must reject the credential request because the attestation signature cannot be verified
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
            wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        });

        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasError("invalid_proof")
                .hasErrorDescription("Key attestation key is not supported or not matching the signature!");
    }

}
