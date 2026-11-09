package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.UseWallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact.CredentialRequestPayload;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.COMPLETE)
@UseWallet(dpop = true, encryption = true, signedMetadata = true)
class IssuerHolderBindingTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-1556",
            summary = "Credential Issuer rejects an attempt to obtain an unbound credential without key proofs",
            description = """
                    Given an offer requiring holder binding, a valid access token, DPoP and encrypted requests.
                    When the Wallet omits proofs from an otherwise valid Credential Request.
                    Then the Issuer returns invalid_proof, issues no credential and preserves the offer state.
                    A conformant retry of the same offer succeeds and every issued credential contains cnf.jwk.
                    Deviation: the Wallet omits proofs required by the advertised proof_types_supported.
                    Spec: OID4VCI 1.0 §8.2 and §8.3.1; Swiss issuance profile §12.2.4.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCI_I1_ISSUING_VERIFIABLE_CREDENTIALS)
    @Tag(ReportingTags.UCI_I1A_CREATE_VERIFIABLE_CREDENTIALS)
    void credentialRequest_whenHolderBindingProofsAreMissing_thenNoUnboundCredentialIsIssued() {
        // Given
        final var offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                CredentialSubjectFixtures.completeEmployeeProfile());
        final var entry = wallet.prepareOffer(toUri(offer.getOfferDeeplink()));
        final var stateBefore = issuerManager.getStatusById(offer.getManagementId()).getStatus();
        final String requestWithoutProofs = CredentialRequestPayload.withoutHolderBindingProofs(
                wallet.createCredentialRequestPayload(entry));

        // When
        final HttpClientErrorException exception = assertThrows(HttpClientErrorException.class,
                () -> wallet.postCredentialRequestWithCustomPayload(entry, requestWithoutProofs));

        // Then
        ApiErrorAssert.assertThat(exception)
                .hasStatus(400)
                .hasError("invalid_proof");
        assertThat(issuerManager.getStatusById(offer.getManagementId()).getStatus())
                .isEqualTo(stateBefore)
                .isNotEqualTo(CredentialStatusType.ISSUED);
        awaitStableIssuerCallbacks();
        assertThat(issuerCallbacks())
                .noneMatch(callback -> CredentialStatusType.ISSUED.getValue().equals(callback.getEvent()));

        // When
        final var response = wallet.postCredentialRequest(entry);

        // Then
        assertThat(response.getStatus())
                .isEqualTo(200);
        SdJwtBatchAssert.assertThat(entry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .haveUniqueHolderBindingKeys();
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.ISSUED);
    }
}
