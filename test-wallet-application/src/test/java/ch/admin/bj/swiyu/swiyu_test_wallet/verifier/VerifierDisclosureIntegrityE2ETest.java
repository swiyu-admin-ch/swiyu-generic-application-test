package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationErrorResponseCode;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact.SdJwtCredential;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.credential.HeldCredential;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.util.function.UnaryOperator;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierDisclosureIntegrityE2ETest extends BaseTest {

    private static final String REQUESTED_CLAIM = "name";
    private static final String FORGED_VALUE = "Mallory Forged";

    @ParameterizedTest(name = "[{index}] reject {0}")
    @EnumSource(DisclosureForgery.class)
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Verifier rejects a Disclosure that the Issuer-signed JWT does not reference",
            description = """
                    Given a holder-bound credential and a pending DCQL verification that requests the name claim.
                    When a malicious holder forges the name Disclosure, either by changing its value or by adding a
                    second, unreferenced name Disclosure, and signs a Key Binding JWT over the forged presentation.
                    Then the Verifier returns HTTP 400, persists the verification as FAILED, never exposes the forged
                    value, and emits exactly one callback.
                    Deviation: The Wallet presents a Disclosure without a matching digest in the signed credential.
                    Spec: RFC 9901 §7.1 (every Disclosure must be referenced by a digest) and §9.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1B)
    @Tag(ReportingTags.EDGE_CASE)
    void presentation_whenDisclosureIsForged_thenFailedWithoutForgedClaimAndOneCallback(
            final DisclosureForgery forgery
    ) {
        // Given
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
        );
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final HeldCredential issued = batchEntry.heldCredential(0);
        final HeldCredential forged = new HeldCredential(
                forgery.apply(SdJwtCredential.parse(issued.sdJwt())).serialize(),
                issued.holderKey(),
                issued.holderPublicKey()
        );

        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withDCQL()
                .createManagementResponse();
        final RequestObject requestObject = wallet.getVerificationRequestObject(
                verification.getVerificationDeeplink()
        );
        final String presentation = forged.present(requestObject.getClientId(), requestObject.getNonce());
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
                .hasDetail(VerificationErrorResponseCode.MALFORMED_CREDENTIAL.getValue())
                .hasErrorCode(VerificationErrorResponseCode.MALFORMED_CREDENTIAL.getValue());

        final ManagementResponse failedVerification = verifierManager.verifyState(
                verification.getId(),
                VerificationStatus.FAILED
        );
        assertThat(failedVerification.getWalletResponse().getErrorCode())
                .isEqualTo(VerificationErrorResponseCode.MALFORMED_CREDENTIAL);
        assertThat(failedVerification.getWalletResponse().getCredentialSubjectData())
                .as("A forged presentation must not expose any credential claims to the Verifier Business System")
                .isNullOrEmpty();
        awaitOneVerifierCallback(callbacksBefore);
        assertThat(awaitStableVerifierCallbacks())
                .isEqualTo(callbacksBefore + 1);
    }

    private enum DisclosureForgery {
        /** Deviation: the name Disclosure keeps its salt but carries another value, so its digest is not referenced. */
        TAMPERED_DISCLOSURE_VALUE(credential -> credential.withTamperedDisclosure(REQUESTED_CLAIM, FORGED_VALUE)),
        /** Deviation: a second, well-formed name Disclosure is appended that no digest references. */
        UNREFERENCED_DISCLOSURE(credential -> credential.withUnreferencedDisclosure(REQUESTED_CLAIM, FORGED_VALUE));

        private final UnaryOperator<SdJwtCredential> forgery;

        DisclosureForgery(final UnaryOperator<SdJwtCredential> forgery) {
            this.forgery = forgery;
        }

        SdJwtCredential apply(final SdJwtCredential credential) {
            return forgery.apply(credential);
        }
    }
}
