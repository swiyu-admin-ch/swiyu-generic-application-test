package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlCredentialMetaDto;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlQueryDto;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.util.List;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.DEFAULT_VCT;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.dcqlClaim;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.defaultDcqlQuery;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierDcqlVctMismatchE2ETest extends BaseTest {

    private static final String OTHER_VCT = DEFAULT_VCT + "-other";

    @Test
    @XrayTest(
            key = "EIDOMNI-1469",
            summary = "Verifier rejects a credential whose vct is not in the DCQL vct_values",
            description = """
                    Given a DCQL verification request whose credential query only accepts another vct.
                    And a valid holder-bound credential of the default vct.
                    When the wallet presents that credential under the query id.
                    Then the verifier rejects the presentation and the verification is FAILED.
                    Deviation: The Wallet deliberately presents a credential whose vct does not match the query.
                    Spec: OID4VP 1.0 §6.4.2 and Appendix B.3.5 (vct_values); §8.6 (the Verifier checks the match).
                    """
    )
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCV_M3_RETRIEVE_VERIFICATION_RESULT)
    @Tag(ReportingTags.UCV_O2_SUBMIT_VERIFICATION_PRESENTATION)
    @Tag(ReportingTags.UCV_O2A_VERIFY_PRESENTATION_SUBMISSION_AND_SD_JWT_CREDENTIAL)
    @Tag(ReportingTags.UCV_O2E_TRIGGER_WEBHOOK_CALLBACK)
    void dcqlPresentation_whenCredentialVctIsNotRequested_thenVerifierRejects() {
        // Given
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
        );
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        final DcqlQueryDto otherVctQuery = defaultDcqlQuery(List.of(dcqlClaim("name")), true);
        otherVctQuery.getCredentials().getFirst().meta(new DcqlCredentialMetaDto()
                .vctValues(List.of(OTHER_VCT))
                .typeValues(null));
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .dcqlQuery(otherVctQuery)
                .createManagementResponse();
        final RequestObject requestObject = wallet.getVerificationRequestObject(
                verification.getVerificationDeeplink()
        );
        final String presentation = batchEntry.createPresentationForSdJwtIndex(0, requestObject);
        final int callbacksBefore = awaitStableVerifierCallbacks();

        // When
        final HttpClientErrorException exception = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.respondToVerification(requestObject, presentation)
        );

        // Then
        ApiErrorAssert.assertThat(exception)
                .hasStatus(400)
                .hasError("invalid_transaction_data")
                .hasDetail("invalid_presentation_submission");
        final ManagementResponse failedVerification = verifierManager.verifyState(
                verification.getId(), VerificationStatus.FAILED);
        assertThat(failedVerification.getWalletResponse().getCredentialSubjectData())
                .isNullOrEmpty();
        awaitOneVerifierCallback(callbacksBefore);
        assertThat(awaitStableVerifierCallbacks())
                .isEqualTo(callbacksBefore + 1);
    }
}
