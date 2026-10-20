package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact.KeyAttestation;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.JwtProof;
import com.nimbusds.jose.jwk.ECKey;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.function.Function;
import java.util.stream.IntStream;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@DisableIfImageTag(
        issuer = {ImageTags.STABLE, ImageTags.RC},
        reason = "This feature is not available yet"
)
class IssuerKeyAttestationValidationTest extends BaseTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final Duration ALREADY_EXPIRED = Duration.ofMinutes(5);

    @ParameterizedTest(name = "[{index}] reject {0}")
    @EnumSource(AttestationDeviation.class)
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Issuer rejects a key proof whose key attestation does not satisfy key_attestations_required",
            description = """
                    Given a pre-authorized offer for a credential configuration with key_attestations_required,
                    an access token and a fresh c_nonce.
                    When the wallet sends otherwise valid key proofs whose key_attestation is missing, attests only
                    iso_18045_enhanced-basic where iso_18045_high is required, attests another key than the proof key,
                    or has expired, while the trusted attestation authority signs it.
                    Then the Issuer rejects the request with HTTP 400 invalid_proof and issues no credential.
                    Deviation: The Wallet omits a required attestation or supplies one with a wrong level, key or expiry.
                    Spec: OID4VCI 1.0 §8.2, Appendix D.1, D.2 and F.1; Swiss issuance profile (key attestation).
                    """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    void credentialRequest_whenKeyAttestationDeviates_thenRejectedWithoutIssuance(final AttestationDeviation deviation) {
        // Given
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                deviation.credentialConfigurationId(),
                CredentialSubjectFixtures.completeEmployeeProfile()
        );
        final WalletBatchEntry batchEntry = wallet.prepareOffer(toUri(offer.getOfferDeeplink()));
        final CredentialStatusType stateBefore = issuerManager.getStatusById(offer.getManagementId()).getStatus();
        final List<String> keyProofs = IntStream.range(0, batchEntry.getHolderKeyPairs().size())
                .mapToObj(index -> {
                    final ECKey holderPublicKey = batchEntry.getHolderPublicKeys().get(index);
                    final JwtProof.JwtProofBuilder keyProof = JwtProof.builder().credentialIssuerURI(
                                    batchEntry.getIssuerMetadata().getCredentialIssuer()).cNonce(
                                    batchEntry.getCNonce()
                            )
                            .keyPair(batchEntry.getHolderKeyPairs().get(index)).publicJwk(holderPublicKey);
                    final String keyAttestation = deviation.apply(KeyAttestation.forKey(holderPublicKey, batchEntry.getCNonce())
                            .signedBy(
                                    mockAttestationAuthority.getSigningPrivateKey(),
                                    mockAttestationAuthority.getKid(),
                                    mockAttestationAuthority.getIssuerClaim()
                            ));
                    return (keyAttestation == null ? keyProof : keyProof.keyAttestation(keyAttestation)).build().toJwt();
                })
                .toList();
        final ObjectNode credentialRequest = (ObjectNode) JSON.readTree(wallet.createCredentialRequestPayload(batchEntry));
        credentialRequest.withObject("proofs").set("jwt", JSON.valueToTree(keyProofs));

        // When
        final HttpClientErrorException exception = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.postCredentialRequestWithCustomPayload(batchEntry, JSON.writeValueAsString(credentialRequest))
        );

        // Then
        ApiErrorAssert.assertThat(exception)
                .hasStatus(400)
                .hasError("invalid_proof");
        assertThat(exception.getResponseBodyAsString())
                .contains(deviation.errorDescription());
        assertThat(issuerManager.getStatusById(offer.getManagementId()).getStatus())
                .as("A rejected key attestation must not issue a credential")
                .isEqualTo(stateBefore);
    }

    private enum AttestationDeviation {
        /** Deviation: no key_attestation, although the configuration requires an iso_18045_high one. */
        MISSING_WHERE_HIGH_IS_REQUIRED(
                CredentialConfigurationFixtures.UNIVERSITY_EXAMPLE_HIGH_KEY_ATTESTATION_REQUIRED_SD_JWT,
                "Attestation was not provided!",
                attestation -> null
        ),
        /** Deviation: no key_attestation, although the configuration requires one of any level. */
        MISSING_WHERE_ANY_IS_REQUIRED(
                CredentialConfigurationFixtures.UNIVERSITY_EXAMPLE_ANY_KEY_ATTESTATION_REQUIRED_SD_JWT,
                "Attestation was not provided!",
                attestation -> null
        ),
        /** Deviation: key_storage is iso_18045_enhanced-basic, below the iso_18045_high the configuration requires. */
        ENHANCED_BASIC_WHERE_HIGH_IS_REQUIRED(
                CredentialConfigurationFixtures.UNIVERSITY_EXAMPLE_HIGH_KEY_ATTESTATION_REQUIRED_SD_JWT,
                "Key attestation was invalid or not matching the attack resistance for the credential!",
                attestation -> attestation.withKeyStorage(KeyAttestation.LEVEL_ENHANCED_BASIC).build()
        ),
        /** Deviation: attested_keys holds another key than the one that signs the key proof. */
        PROOF_KEY_NOT_ATTESTED(
                CredentialConfigurationFixtures.UNIVERSITY_EXAMPLE_HIGH_KEY_ATTESTATION_REQUIRED_SD_JWT,
                "Proof key does not match any key listed in the attestation's attested_keys",
                attestation -> attestation.withAttestedKey(ECCryptoSupport.toPublicJwk(
                        ECCryptoSupport.generateECKeyPair().getPublic(), "unrelated-key")).build()
        ),
        /** Deviation: exp is in the past. */
        EXPIRED(
                CredentialConfigurationFixtures.UNIVERSITY_EXAMPLE_HIGH_KEY_ATTESTATION_REQUIRED_SD_JWT,
                "Attestation has been rejected! Bad Attestation JWT - Expired JWT",
                attestation -> attestation.withExpiration(Instant.now().minus(ALREADY_EXPIRED)).build()
        );

        private final String configurationId;
        private final String expectedDescription;
        private final Function<KeyAttestation.Builder, String> deviation;

        AttestationDeviation(
                final String credentialConfigurationId,
                final String errorDescription,
                final Function<KeyAttestation.Builder, String> deviation
        ) {
            this.configurationId = credentialConfigurationId;
            this.expectedDescription = errorDescription;
            this.deviation = deviation;
        }

        String credentialConfigurationId() {
            return configurationId;
        }

        String errorDescription() {
            return expectedDescription;
        }

        /** The key_attestation header value, or {@code null} to send the proof without one. */
        String apply(final KeyAttestation.Builder conformantAttestation) {
            return deviation.apply(conformantAttestation);
        }
    }
}
