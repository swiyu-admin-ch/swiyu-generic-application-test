package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.verifier.model.ConfigurationOverrideDto;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseVerifiers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletProfile;
import com.nimbusds.jose.JWSAlgorithm;
import com.google.gson.JsonParser;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.RestClientResponseException;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.HSM)
@UseVerifiers(VerifierVariant.HSM)
@EnabledIfSystemProperty(
        named = "hsm",
        matches = "true",
        disabledReason = "HSM tests require -Dhsm=true so SoftHSM is injected only when explicitly requested."
)
class VerifierHSMTest extends BaseTest {

    private static final String DEFAULT_HSM_KEY_ID = "01";
    private static final String OVERRIDE_HSM_KEY_ID = "02";

    @Test
    @XrayTest(
            key = "EIDOMNI-967",
            summary = "Verifier signs request object with override HSM key id without key pin",
            description = """
                    This test validates that the Business Verifier management API honors a ConfigurationOverride
                    containing only key_id when signing a JWT-secured OID4VP request object, using the default HSM
                    key PIN and the override key instead of the configured default HSM key.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1A)
    @Tag(ReportingTags.EDGE_CASE)
    void signedRequestObject_withOnlyOverrideHsmKeyId_thenUsesOverrideKey() throws Exception {
        // Given
        final ConfigurationOverrideDto configurationOverride = new ConfigurationOverrideDto()
                .verifierDid(issuerConfig.getIssuerDid())
                .verificationMethod(issuerConfig.getIssuerAuthKeyId())
                .keyId(OVERRIDE_HSM_KEY_ID);

        assertThat(configurationOverride.getKeyPin())
                .as("The regression scenario must provide only key_id in ConfigurationOverride")
                .isNull();

        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL()
                .jwtSecure()
                .configurationOverride(configurationOverride)
                .createManagementResponse();

        // When
        final SignedJWT requestObject = SignedJWT.parse(
                wallet.getVerificationDetailSigned(verification.getVerificationDeeplink())
        );

        // Then
        assertThat(requestObject.getHeader().getKeyID())
                .as("The signed request object must advertise the configured verifier verification method")
                .isEqualTo(issuerConfig.getIssuerAuthKeyId());
        assertThat(isSignedByHsmKey(requestObject, OVERRIDE_HSM_KEY_ID))
                .as("The request object should be signed with the HSM key from ConfigurationOverride.key_id")
                .isTrue();
        assertThat(isSignedByHsmKey(requestObject, DEFAULT_HSM_KEY_ID))
                .as("The request object should not fall back to the verifier's default HSM key")
                .isFalse();
    }

    @ParameterizedTest(name = "override={0}, key_pin={1}")
    @CsvSource({"false,", "true,", "true,''", "true,1234"})
    @XrayTest(
            key = "EIDOMNI-1431",
            summary = "Verifier completes a verification with its selected HSM key and matching client identity",
            description = """
                    Given an HSM Verifier using its default identity or a per-verification override with an optional key_pin.
                    When the Wallet validates the signed Request Object and sends an encrypted bound presentation.
                    Then the signature verifies only with the selected key, kid and client_id identify the same DID and verification reaches SUCCESS.
                    Spec: Verifier management ConfigurationOverride; OID4VP 1.0 sections 5.9.3 and 8.6; Swiss verification section 5.
                    """)
    @Tag(ReportingTags.UCV_O1A)
    @Tag(ReportingTags.HAPPY_PATH)
    void signedRequestObject_whenHsmIdentityIsSelected_thenVerificationUsesThatIdentity(
            final boolean overridden, final String keyPin) throws Exception {
        // Given
        wallet.setProfile(WalletProfile.swiss());
        final var offer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final var entry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final String expectedDid = overridden ? issuerConfig.getIssuerDid() : verifierConfig.getVerifierDid();
        final String expectedKid = overridden ? issuerConfig.getIssuerAuthKeyId() : verifierConfig.getVerifierAuthKeyId();
        final String expectedDidLog = overridden ? issuerConfig.getIssuerDidLog() : verifierConfig.getVerifierDidLog();
        final ConfigurationOverrideDto override = overridden ? new ConfigurationOverrideDto()
                .verifierDid(expectedDid)
                .verificationMethod(expectedKid)
                .keyId(OVERRIDE_HSM_KEY_ID)
                .keyPin(keyPin) : null;
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL()
                .jwtSecure()
                .encrypted()
                .configurationOverride(override)
                .createManagementResponse();

        // When
        final SignedJWT jwt = SignedJWT.parse(wallet.getVerificationDetailSigned(verification.getVerificationDeeplink()));
        final RequestObject request = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());

        // Then
        assertThat(jwt.getHeader().getAlgorithm())
                .isEqualTo(JWSAlgorithm.ES256);
        assertThat(jwt.getHeader().getKeyID())
                .isEqualTo(expectedKid);
        assertThat(jwt.getJWTClaimsSet().getStringClaim("client_id"))
                .isEqualTo("decentralized_identifier:" + expectedDid)
                .isEqualTo(request.getClientId());
        assertThat(jwt.getJWTClaimsSet().getStringClaim("nonce"))
                .isNotBlank()
                .isEqualTo(request.getNonce());
        assertThat(isSignedByHsmKey(jwt, OVERRIDE_HSM_KEY_ID))
                .isEqualTo(overridden);
        assertThat(isSignedByHsmKey(jwt, DEFAULT_HSM_KEY_ID))
                .isEqualTo(!overridden);
        assertThat(jwt.verify(new ECDSAVerifier(signingKeyFromDidLog(expectedDidLog, expectedKid))))
                .as("The public key advertised by the selected DID must verify the HSM signature")
                .isTrue();

        // When
        final int callbacksBefore = countVerifierCallbacks();
        wallet.respondToVerification(request, entry.createPresentationForSdJwtIndex(0, request));

        // Then
        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
        awaitOneVerifierCallback(callbacksBefore);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1432",
            summary = "Verifier isolates default and override HSM signers across interleaved Request Object retrievals",
            description = """
                    Given default and override-key verification requests in one Verifier runtime.
                    When the Wallet retrieves each signed Request Object repeatedly in alternating order.
                    Then every signature, kid and client_id still belongs to its own request and both transactions remain PENDING.
                    Spec: Verifier management ConfigurationOverride, scope limited to one verification; OID4VP 1.0 section 5.9.3.
                    """)
    @Tag(ReportingTags.UCV_O1A)
    @Tag(ReportingTags.EDGE_CASE)
    void signedRequestObject_whenHsmOverridesAreInterleaved_thenEachRequestKeepsItsOwnSigner() throws Exception {
        // Given
        final ManagementResponse defaultVerification = verifierManager.verificationRequest()
                .withUniversityDCQL()
                .jwtSecure()
                .createManagementResponse();
        final ManagementResponse overrideVerification = verifierManager.verificationRequest()
                .withUniversityDCQL()
                .jwtSecure()
                .configurationOverride(new ConfigurationOverrideDto()
                        .verifierDid(issuerConfig.getIssuerDid())
                        .verificationMethod(issuerConfig.getIssuerAuthKeyId())
                        .keyId(OVERRIDE_HSM_KEY_ID))
                .createManagementResponse();

        // When / Then
        for (ManagementResponse verification : List.of(
                overrideVerification, defaultVerification, overrideVerification, defaultVerification)) {
            final boolean overridden = verification.getId().equals(overrideVerification.getId());
            final SignedJWT jwt = SignedJWT.parse(wallet.getVerificationDetailSigned(verification.getVerificationDeeplink()));
            assertThat(jwt.getHeader().getKeyID())
                    .isEqualTo(overridden ? issuerConfig.getIssuerAuthKeyId() : verifierConfig.getVerifierAuthKeyId());
            assertThat(jwt.getJWTClaimsSet().getStringClaim("client_id"))
                    .isEqualTo("decentralized_identifier:" +
                            (overridden ? issuerConfig.getIssuerDid() : verifierConfig.getVerifierDid()));
            assertThat(isSignedByHsmKey(jwt, OVERRIDE_HSM_KEY_ID))
                    .isEqualTo(overridden);
            assertThat(isSignedByHsmKey(jwt, DEFAULT_HSM_KEY_ID))
                    .isEqualTo(!overridden);
        }
        verifierManager.verifyState(defaultVerification.getId(), VerificationStatus.PENDING);
        verifierManager.verifyState(overrideVerification.getId(), VerificationStatus.PENDING);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1433",
            summary = "Verifier rejects an unknown override HSM key even after its default signer is cached",
            description = """
                    Given a Verifier that already served a valid default-key Request Object.
                    When the Wallet fetches a different request selecting a nonexistent HSM key.
                    Then retrieval fails without a signed Request Object or callback, and a later default request still signs correctly.
                    Deviation: the Business Verifier selects an HSM key absent from the token.
                    Spec: Verifier management ConfigurationOverride; fail-closed signing invariant, exact HTTP error mapping Unknown.
                    """)
    @Tag(ReportingTags.UCV_O1A)
    @Tag(ReportingTags.EDGE_CASE)
    void signedRequestObject_whenOverrideKeyDoesNotExist_thenDoesNotReuseCachedDefaultSigner() throws Exception {
        // Given
        final ManagementResponse warmup = verifierManager.verificationRequest()
                .withUniversityDCQL().jwtSecure().createManagementResponse();
        final SignedJWT warmupJwt = SignedJWT.parse(wallet.getVerificationDetailSigned(warmup.getVerificationDeeplink()));
        assertThat(isSignedByHsmKey(warmupJwt, DEFAULT_HSM_KEY_ID))
                .isTrue();
        final ManagementResponse invalid = verifierManager.verificationRequest()
                .withUniversityDCQL()
                .jwtSecure()
                .configurationOverride(new ConfigurationOverrideDto().keyId("missing-hsm-request-key"))
                .createManagementResponse();
        final int callbacksBefore = countVerifierCallbacks();

        // When
        final RestClientResponseException error = assertThrows(RestClientResponseException.class,
                () -> wallet.getVerificationDetailSigned(invalid.getVerificationDeeplink()));

        // Then
        assertThat(error.getStatusCode().isError())
                .isTrue();
        verifierManager.verifyState(invalid.getId(), VerificationStatus.PENDING);
        assertThat(countVerifierCallbacks())
                .isEqualTo(callbacksBefore);

        // When
        final ManagementResponse healthy = verifierManager.verificationRequest()
                .withUniversityDCQL().jwtSecure().createManagementResponse();
        final SignedJWT healthyJwt = SignedJWT.parse(wallet.getVerificationDetailSigned(healthy.getVerificationDeeplink()));

        // Then
        assertThat(healthyJwt.getHeader().getKeyID())
                .isEqualTo(verifierConfig.getVerifierAuthKeyId());
        assertThat(isSignedByHsmKey(healthyJwt, DEFAULT_HSM_KEY_ID))
                .isTrue();
        assertThat(isSignedByHsmKey(healthyJwt, OVERRIDE_HSM_KEY_ID))
                .isFalse();
    }

    private ECKey signingKeyFromDidLog(final String didLog, final String keyId) throws Exception {
        final var methods = JsonParser.parseString(didLog).getAsJsonObject()
                .getAsJsonObject("state").getAsJsonArray("verificationMethod");
        for (var method : methods) {
            final var candidate = method.getAsJsonObject();
            if (keyId.equals(candidate.get("id").getAsString())) {
                return JWK.parse(candidate.getAsJsonObject("publicKeyJwk").toString()).toECKey();
            }
        }
        throw new IllegalArgumentException("No public verification method published for " + keyId);
    }

    private boolean isSignedByHsmKey(final SignedJWT jwt, final String keyId) throws Exception {
        final String certificateResourcePath = "softhsm/keys/%s-cert.pem".formatted(keyId);
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(certificateResourcePath)) {
            assertThat(inputStream)
                    .as("HSM public certificate should be available: %s", certificateResourcePath)
                    .isNotNull();
            final String certificatePem = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
            return jwt.verify(new ECDSAVerifier(JWK.parseFromPEMEncodedX509Cert(certificatePem).toECKey()));
        }
    }
}
