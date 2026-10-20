package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.CreateCredentialOfferRequest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialOfferMetadataDto;
import ch.admin.bj.swiyu.gen.issuer.model.StatusListCreate;
import ch.admin.bj.swiyu.gen.issuer.model.StatusListCreateConfig;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationErrorResponseCode;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact.SdJwtCredential;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.util.List;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierStatusListValidityE2ETest extends BaseTest {

    /** Far beyond any status list the Credential Issuer creates in these tests. */
    private static final int INDEX_OUTSIDE_THE_LIST = 50_000_000;

    @ParameterizedTest(name = "[{index}] reject {0}")
    @EnumSource(StatusListFailure.class)
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Verifier fails a verification whose credential status cannot be established",
            description = """
                    Given a holder-bound credential with a status list reference and a pending DCQL verification.
                    When the Status Registry serves a correctly signed Status List Token whose exp has passed,
                    or the credential, signed again by the Credential Issuer, references an index outside the list.
                    Then the Verifier returns HTTP 400, persists the verification as FAILED with the specific error,
                    and emits exactly one callback instead of treating the credential as valid.
                    Deviation: The Status Registry serves an expired token or the Credential Issuer signs an out-of-range index.
                    Spec: Token Status List draft 20 §5.1 (exp), §6.2 and §8.3; Swiss VC profile Token Status List §5.1.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1B)
    @Tag(ReportingTags.EDGE_CASE)
    void presentation_whenStatusCannotBeEstablished_thenFailedWithStoredErrorAndOneCallback(
            final StatusListFailure failure
    ) {
        // Given
        // A fresh URI makes the status check independent of the Verifier's status-list cache.
        final var statusList = issuerManager.getStatusListApi().createStatusList(new StatusListCreate()
                .maxLength(100000)
                .config(new StatusListCreateConfig().bits(2)));
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredential(new CreateCredentialOfferRequest()
                .metadataCredentialSupportedId(List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT))
                .credentialSubjectData(CredentialSubjectFixtures.completeEmployeeProfile())
                .credentialMetadata(new CredentialOfferMetadataDto().deferred(false))
                .offerValiditySeconds(600)
                .statusLists(List.of(statusList.getStatusRegistryUrl())));
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        applyFailure(failure, batchEntry);

        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withDCQL()
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
                .hasDetail(failure.errorCode().getValue())
                .hasErrorCode(failure.errorCode().getValue());

        final ManagementResponse failedVerification = verifierManager.verifyState(
                verification.getId(),
                VerificationStatus.FAILED
        );
        assertThat(failedVerification.getWalletResponse().getErrorCode())
                .isEqualTo(failure.errorCode());
        assertThat(failedVerification.getWalletResponse().getCredentialSubjectData())
                .isNullOrEmpty();
        awaitOneVerifierCallback(callbacksBefore);
        assertThat(awaitStableVerifierCallbacks())
                .isEqualTo(callbacksBefore + 1);
    }

    private void applyFailure(final StatusListFailure failure, final WalletBatchEntry batchEntry) {
        switch (failure) {
            case EXPIRED_STATUS_LIST_TOKEN -> mockServices.enableExpiredStatusListToken();
            // Deviation: only status.status_list.idx changes; the Credential Issuer's own key signs the credential again.
            case STATUS_INDEX_OUTSIDE_THE_LIST -> batchEntry.replaceIssuedCredential(
                    0,
                    SdJwtCredential.parse(batchEntry.getVerifiableCredential(0)).resign()
                            .signedWith(issuerConfig.getKeyPair())
                            .withStatusIndex(INDEX_OUTSIDE_THE_LIST)
                            .build()
                            .serialize()
            );
        }
    }

    private enum StatusListFailure {
        EXPIRED_STATUS_LIST_TOKEN(VerificationErrorResponseCode.UNRESOLVABLE_STATUS_LIST),
        STATUS_INDEX_OUTSIDE_THE_LIST(VerificationErrorResponseCode.UNRESOLVABLE_STATUS_LIST);

        private final VerificationErrorResponseCode expectedError;

        StatusListFailure(final VerificationErrorResponseCode errorCode) {
            this.expectedError = errorCode;
        }

        VerificationErrorResponseCode errorCode() {
            return expectedError;
        }
    }
}
