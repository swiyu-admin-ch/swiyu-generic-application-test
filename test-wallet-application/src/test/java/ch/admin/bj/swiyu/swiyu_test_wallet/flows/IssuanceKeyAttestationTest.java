package ch.admin.bj.swiyu.swiyu_test_wallet.flows;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockAttestationAuthority;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.web.client.HttpClientErrorException;

import java.net.URI;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig.UNTRUSTED_REGISTRY_HOST;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockserver.model.HttpRequest.request;

public class IssuanceKeyAttestationTest extends BaseTest {

    @AfterEach
    void restoreDefaultAttestationAuthority() {
        wallet.setMockAttestationAuthority(mockAttestationAuthority);
    }

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
            issuer = {ImageTags.STABLE, ImageTags.RC},
            reason = "This feature is not available yet"
    )
    void boundNonDeferredCredential_whenKeyAttestationIsValid_thenSuccess() {
        // Given
        wallet.setMockAttestationAuthority(mockAttestationAuthority);
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.UNIVERSITY_EXAMPLE_HIGH_KEY_ATTESTATION_REQUIRED_SD_JWT;

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
                    .getVerificationRequestObject(verification.getVerificationDeeplink());
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
            issuer = {ImageTags.STABLE, ImageTags.RC},
            reason = "This feature is not available yet"
    )
    void boundNonDeferredCredential_whenKeyAttestationSignatureIsMismatched_thenIssuanceRejected() {
        // Given
        wallet.setMockAttestationAuthority(mockAttestationAuthority.withMismatchedSigningKey());
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId = CredentialConfigurationFixtures.UNIVERSITY_EXAMPLE_HIGH_KEY_ATTESTATION_REQUIRED_SD_JWT;

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

    @ParameterizedTest(name = "[{index}] key attestation with {0} iss claim")
    @EnumSource(AttestationIssuerClaim.class)
    @XrayTest(
            key = "EIDOMNI-1360",
            summary = "Generic Issuer ignores a missing or mismatched iss claim in key attestations",
            description = """
                    Given a valid key attestation signed by the trusted DID identified by its kid header,
                    while the iss claim is either absent or different from that DID.
                    When the wallet requests a bound SD-JWT credential.
                    Then the Generic Issuer trusts the signer identified by kid and issues the credential.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC},
            reason = "EIDOMNI-1360 requires centralized JWT validation in the Generic Issuer"
    )
    void boundNonDeferredCredential_whenKeyAttestationIssuerClaimIsIgnored_thenSuccess(
            final AttestationIssuerClaim issuerClaim
    ) {
        // Given
        wallet.setMockAttestationAuthority(
                mockAttestationAuthority.withIssuerClaim(issuerClaim.value())
        );
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String supportedMetadataId =
                CredentialConfigurationFixtures.UNIVERSITY_EXAMPLE_HIGH_KEY_ATTESTATION_REQUIRED_SD_JWT;
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                supportedMetadataId,
                subjectClaims
        );

        // When
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        // Then
        SdJwtBatchAssert.assertThat(batchEntry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1361",
            summary = "Generic Issuer rejects key-attestation DIDs outside the swiyu Base Registry",
            description = """
                    Given a key attestation whose kid resolves to a reachable host outside the configured Base Registry allowlist.
                    When the wallet requests a bound SD-JWT credential.
                    Then the Generic Issuer rejects the proof before making any request to that host.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC},
            reason = "EIDOMNI-1361 requires centralized JWT validation in the Generic Issuer"
    )
    void boundNonDeferredCredential_whenAttestationDidIsOutsideBaseRegistry_thenRejectedWithoutResolution() {
        // Given
        final URI registryEntry = URI.create(
                "https://%s/api/v1/did/%s".formatted(
                        UNTRUSTED_REGISTRY_HOST,
                        UUID.randomUUID()
                )
        );
        final MockAttestationAuthority externalAuthority = new MockAttestationAuthority(registryEntry);
        final String didDocumentPath = registryEntry.getPath() + "/did.jsonl";
        mockServerClientConfig.replaceDidLog(externalAuthority.getDid(), externalAuthority.getDidLog());
        wallet.setMockAttestationAuthority(externalAuthority);

        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.UNIVERSITY_EXAMPLE_HIGH_KEY_ATTESTATION_REQUIRED_SD_JWT,
                CredentialSubjectFixtures.completeEmployeeProfile()
        );
        final int requestsBefore = mockServerClient.retrieveRecordedRequests(
                request()
                        .withMethod("GET")
                        .withPath(didDocumentPath)
        ).length;

        // When
        final HttpClientErrorException exception = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.collectOffer(toUri(offer.getOfferDeeplink()))
        );

        // Then
        ApiErrorAssert.assertThat(exception)
                .hasStatus(400)
                .hasError("invalid_proof");
        assertThat(exception.getResponseBodyAsString())
                .as("The rejection must come from the Base Registry allowlist")
                .contains("Base Registry allowlist");
        assertThat(mockServerClient.retrieveRecordedRequests(
                request()
                        .withMethod("GET")
                        .withPath(didDocumentPath)
        ))
                .as("The Issuer must reject the DID before attempting resolution")
                .hasSize(requestsBefore);
    }

    private enum AttestationIssuerClaim {
        MISSING(null),
        MISMATCHED("did:example:untrusted-attestation-issuer");

        private final String value;

        AttestationIssuerClaim(final String value) {
            this.value = value;
        }

        String value() {
            return value;
        }
    }

}
