package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.TrustMethod;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ContainerLogConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.testcontainers.containers.GenericContainer;

import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result.VerificationFailureAssert.assertIssuerUntrusted;
import static ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result.VerificationFailureAssert.assertRejected;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.DEFAULT_CREDENTIAL_ID;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class TrustAnchorVerificationTest extends BaseTest {

    @Autowired
    private ContainerLogConfig containerLogConfig;

    @Test
    @XrayTest(
            key = "EIDOMNI-195",
            summary = "Successful verification through a valid Trust Anchor",
            description = """
                    This test validates that a verifier successfully accepts a credential issued by a trusted issuer
                    when verified through a configured Trust Anchor. The verification succeeds for both SWIYU API versions
                    (OID4VP standard and DCQL-based), ensuring that trust relationships are properly validated.
                    """
    )
    @Tag(ReportingTags.HAPPY_PATH)
    @Tag(ReportingTags.UCV_O2_SUBMIT_VERIFICATION_PRESENTATION)
    @Tag(ReportingTags.UCV_O2A_VERIFY_PRESENTATION_SUBMISSION_AND_SD_JWT_CREDENTIAL)
    @Tag(ReportingTags.UCV_O2F_VALIDATE_ISSUER_VIA_TRUST_REGISTRY_TP2_VERIFIER_VIEW)
    void verificationWithValidTrustAnchor_thenSuccess() {
        // Given
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(response.getOfferDeeplink()));
        assertThat(batchEntry.getCredentialOffer()).isNotNull();

        // TP2 takes its trust anchor from the Verifier environment, not from the management request.
        try (final GenericContainer<?> trustedVerifierContainer = createVerifierWithTrustAnchor(trustConfig.getTrustDid())) {
            trustedVerifierContainer.start();
            final BusinessVerifier trustedVerifier = new BusinessVerifier("http://%s:%d".formatted(
                    trustedVerifierContainer.getHost(), trustedVerifierContainer.getMappedPort(8080)));
            wallet.useVerifier(new ServiceLocationContext(
                    trustedVerifierContainer.getHost(), trustedVerifierContainer.getMappedPort(8080).toString()));
            wallet.setUseEncryption(true);

            // When
            final ManagementResponse verification = trustedVerifier.verificationRequest()
                    .withDCQL()
                    .encrypted()
                    .createManagementResponse();
            final RequestObject verificationDetails = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
            final String presentation = batchEntry.createPresentationForSdJwtIndex(0, verificationDetails);
            wallet.respondToVerification(verificationDetails, presentation);

            // Then
            final ManagementResponse result = trustedVerifier.verifyState(verification.getId(), VerificationStatus.SUCCESS);
            assertThat(result.getCredentialEvaluation())
                    .containsOnlyKeys(DEFAULT_CREDENTIAL_ID);
            assertThat(result.getCredentialEvaluation().get(DEFAULT_CREDENTIAL_ID))
                    .singleElement()
                    .satisfies(evaluation -> {
                        assertThat(evaluation.getTrustMarkers())
                                .isNotNull();
                        assertThat(evaluation.getTrustMarkers().getIsTrusted())
                                .isTrue();
                        assertThat(evaluation.getTrustMarkers().getTrustMethod())
                                .isEqualTo(TrustMethod.TRUST_PROTOCOL_2_0);
                    });
        } finally {
            wallet.useVerifier(currentVerifier);
        }
    }

    private GenericContainer<?> createVerifierWithTrustAnchor(final String trustIssuerDid) {
        final var imageConfig = VerifierVariant.DEFAULT.imageConfig(verifierImageConfig);
        imageConfig.setSurname("trust_anchor_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16));
        return VerifierContainerConfig.createVerifierContainer(
                verifierContainer.getNetwork(),
                dbTestContainer,
                verifierConfig,
                verifierContainer.getDockerImageName(),
                imageConfig,
                managementAuthConfig,
                null,
                containerLogConfig
        ).withEnv("SWIYU_TRUST_ISSUER_DID", trustIssuerDid);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-397",
            summary = "Verification rejected when issuer not trusted via Trust Anchor",
            description = """
                    This test ensures that verification fails when the issuer is not trusted through the provided
                    Trust Anchor. The test validates that trust anchor validation prevents accepting credentials from
                    untrusted issuers across both SWIYU API versions.
                    """
    )
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCV_O2_SUBMIT_VERIFICATION_PRESENTATION)
    @Tag(ReportingTags.UCV_O2A_VERIFY_PRESENTATION_SUBMISSION_AND_SD_JWT_CREDENTIAL)
    @Tag(ReportingTags.UCV_O2F_VALIDATE_ISSUER_VIA_TRUST_REGISTRY_TP2_VERIFIER_VIEW)
    void verificationWithUntrustedIssuer_thenFails() {
        // Given
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(response.getOfferDeeplink()));
        assertThat(batchEntry.getCredentialOffer()).isNotNull();

        // The configured anchor differs from the signer of the issuer's Trust Statements.
        try (final GenericContainer<?> untrustedVerifierContainer = createVerifierWithTrustAnchor(verifierConfig.getVerifierDid())) {
            untrustedVerifierContainer.start();
            final BusinessVerifier untrustedVerifier = new BusinessVerifier("http://%s:%d".formatted(
                    untrustedVerifierContainer.getHost(), untrustedVerifierContainer.getMappedPort(8080)));
            wallet.useVerifier(new ServiceLocationContext(
                    untrustedVerifierContainer.getHost(), untrustedVerifierContainer.getMappedPort(8080).toString()));
            wallet.setUseEncryption(true);

            // When
            final ManagementResponse verification = untrustedVerifier.verificationRequest()
                    .withDCQL()
                    .encrypted()
                    .createManagementResponse();
            final RequestObject verificationDetails = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
            final String presentation = batchEntry.createPresentationForSdJwtIndex(0, verificationDetails);

            // Then
            assertRejected(
                    () -> wallet.respondToVerification(verificationDetails, presentation),
                    untrustedVerifier,
                    verification.getId(),
                    ex -> ApiErrorAssert.assertThat(ex)
                            .hasStatus(400)
                            .hasError("invalid_transaction_data")
                            .hasDetail("issuer_not_accepted")
                            .hasErrorDescription("Issuer not in list of accepted issuers or connected to trust anchor"),
                    evaluation -> assertIssuerUntrusted(evaluation)
            );
        } finally {
            wallet.useVerifier(currentVerifier);
        }
    }
}
