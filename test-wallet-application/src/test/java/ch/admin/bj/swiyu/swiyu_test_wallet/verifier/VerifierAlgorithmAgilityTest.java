package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationErrorResponseCode;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.mock.MockServices;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.identity.DidLogUtil;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact.KeyBindingJwt;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact.SdJwtCredential;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;
import tools.jackson.databind.JsonNode;

import java.net.URI;
import java.text.ParseException;
import java.util.List;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@DisableIfImageTag(
        verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
        reason = "Ed25519 verification is introduced by the Generic Verifier expand phase."
)
class VerifierAlgorithmAgilityTest extends BaseTest {

    private static final List<String> EXPAND_PHASE_ALGORITHMS = List.of("ES256", "Ed25519");

    @Test
    @XrayTest(
            key = "EIDOMNI-1278",
            summary = "Verifier metadata advertises ES256 and Ed25519 for SD-JWT and KB-JWT",
            description = """
                    Given a Generic Verifier configured for the Ed25519 expand phase.
                    When a wallet retrieves its public OpenID client metadata.
                    Then both sd-jwt_alg_values and kb-jwt_alg_values contain exactly ES256 and Ed25519,
                    preserving backward compatibility without advertising an unknown algorithm.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1A)
    @Tag(ReportingTags.HAPPY_PATH)
    void openIdClientMetadata_whenExpandAlgorithmsAreConfigured_thenAdvertisesBothAlgorithms() {
        final JsonNode metadata = restClient.get()
                .uri(verifierUrl("/oid4vp/api/openid-client-metadata.json"))
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .body(JsonNode.class);

        assertThat(metadata).isNotNull();
        assertAlgorithms(metadata, "sd-jwt_alg_values");
        assertAlgorithms(metadata, "kb-jwt_alg_values");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1279",
            summary = "Verifier accepts an Ed25519 issuer-signed SD-JWT with an ES256 key binding",
            description = """
                    Given a holder-bound SD-JWT whose issuer signature and DID assertion key use Ed25519.
                    And the hardware-bound holder key and KB-JWT continue to use ES256.
                    When the wallet submits the presentation through the complete OID4VP flow.
                    Then the Generic Verifier validates the Ed25519 credential signature and completes successfully.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1B)
    @Tag(ReportingTags.HAPPY_PATH)
    @EnabledIfSystemProperty(
            named = "didresolver.version",
            matches = "2\\.9\\.0",
            disabledReason = "Requires a verifier image with didresolver 2.9.0; enable with -Ddidresolver.version=2.9.0."
    )
    void verification_whenIssuerSdJwtUsesEd25519_thenSucceeds() throws Exception {
        final WalletBatchEntry batchEntry = issueBoundCredential();
        final Ed25519Issuer edIssuer = createEd25519Issuer();
        final String ed25519Credential = resignCredentialWithEd25519Issuer(
                batchEntry.getVerifiableCredential(0),
                edIssuer
        );
        replaceIssuedCredential(batchEntry, ed25519Credential);

        final ManagementResponse verification = createVerification(edIssuer.did());
        final RequestObject requestObject = wallet.getVerificationRequestObject(
                verification.getVerificationDeeplink()
        );
        final String presentation = batchEntry.createPresentationForSdJwtIndex(0, requestObject);

        assertThat(issuerJwt(ed25519Credential).getHeader().getAlgorithm())
                .isEqualTo(JWSAlgorithm.Ed25519);
        assertThat(keyBindingJwt(presentation).getHeader().getAlgorithm())
                .as("Hardware-bound holder key remains P-256/ES256")
                .isEqualTo(JWSAlgorithm.ES256);

        wallet.respondToVerification(requestObject, presentation);

        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1280",
            summary = "Verifier accepts an Ed25519 key-binding JWT",
            description = """
                    Given an ES256 issuer-signed SD-JWT whose cnf claim contains an Ed25519 holder key.
                    When the wallet creates a valid Ed25519 KB-JWT and submits the presentation through OID4VP.
                    Then the Generic Verifier validates the key-binding signature and completes successfully.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1B)
    @Tag(ReportingTags.HAPPY_PATH)
    void verification_whenKeyBindingJwtUsesEd25519_thenSucceeds() throws Exception {
        final WalletBatchEntry batchEntry = issueBoundCredential();
        final OctetKeyPair holderKey = generateEd25519Key("holder-key");
        final String holderBoundCredential = replaceHolderKey(
                batchEntry.getVerifiableCredential(0),
                holderKey
        );
        replaceIssuedCredential(batchEntry, holderBoundCredential);

        final ManagementResponse verification = createVerification(issuerConfig.getIssuerDid());
        final RequestObject requestObject = wallet.getVerificationRequestObject(
                verification.getVerificationDeeplink()
        );
        final String presentation = createEd25519Presentation(
                holderBoundCredential,
                requestObject,
                holderKey
        );

        assertThat(issuerJwt(holderBoundCredential).getHeader().getAlgorithm())
                .as("Existing issuer artifacts remain verifiable with ES256")
                .isEqualTo(JWSAlgorithm.ES256);
        assertThat(keyBindingJwt(presentation).getHeader().getAlgorithm())
                .isEqualTo(JWSAlgorithm.Ed25519);

        wallet.respondToVerification(requestObject, presentation);

        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
    }

    @ParameterizedTest(name = "[{index}] reject corrupted Ed25519 {0} signature")
    @EnumSource(Ed25519SignatureTarget.class)
    @XrayTest(
            key = "EIDOMNI-1281",
            summary = "Verifier strictly rejects invalid Ed25519 SD-JWT and KB-JWT signatures",
            description = """
                    Given a structurally valid Ed25519 SD-JWT or KB-JWT whose compact JWS signature is corrupted.
                    When a wallet submits the presentation through the complete OID4VP boundary.
                    Then the Generic Verifier rejects it with the signature-specific error, persists FAILED,
                    and never accepts an Ed25519 artifact merely because its alg header is allowed.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1B)
    @Tag(ReportingTags.EDGE_CASE)
    @EnabledIfSystemProperty(
            named = "didresolver.version",
            matches = "2\\.9\\.0",
            disabledReason = "Requires a verifier image with didresolver 2.9.0; enable with -Ddidresolver.version=2.9.0."
    )
    void verification_whenEd25519SignatureIsInvalid_thenStrictlyRejected(
            final Ed25519SignatureTarget signatureTarget
    ) throws Exception {
        final InvalidPresentationScenario scenario = invalidPresentation(signatureTarget);

        final HttpClientErrorException exception = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.respondToVerification(scenario.requestObject(), scenario.presentation())
        );

        ApiErrorAssert.assertThat(exception)
                .hasStatus(400)
                .hasError("invalid_transaction_data")
                .hasDetail(signatureTarget.errorCode().getValue())
                .hasErrorCode(signatureTarget.errorCode().getValue());

        final ManagementResponse failed = verifierManager.verifyState(
                scenario.verificationId(),
                VerificationStatus.FAILED
        );
        assertThat(failed.getWalletResponse().getErrorDescription())
                .as("The failure must come from signature verification, not from an unsupported alg allowlist")
                .contains(signatureTarget.signatureFailureMessage());
    }

    private InvalidPresentationScenario invalidPresentation(
            final Ed25519SignatureTarget signatureTarget
    ) throws Exception {
        final WalletBatchEntry batchEntry = issueBoundCredential();

        if (signatureTarget == Ed25519SignatureTarget.ISSUER_SD_JWT) {
            final Ed25519Issuer edIssuer = createEd25519Issuer();
            final String validCredential = resignCredentialWithEd25519Issuer(
                    batchEntry.getVerifiableCredential(0),
                    edIssuer
            );
            final String invalidCredential = corruptIssuerSignature(validCredential);
            replaceIssuedCredential(batchEntry, invalidCredential);

            final ManagementResponse verification = createVerification(edIssuer.did());
            final RequestObject requestObject = wallet.getVerificationRequestObject(
                    verification.getVerificationDeeplink()
            );
            final String presentation = batchEntry.createPresentationForSdJwtIndex(0, requestObject);
            return new InvalidPresentationScenario(verification.getId(), requestObject, presentation);
        }

        final OctetKeyPair holderKey = generateEd25519Key("holder-key");
        final String credential = replaceHolderKey(batchEntry.getVerifiableCredential(0), holderKey);
        final ManagementResponse verification = createVerification(issuerConfig.getIssuerDid());
        final RequestObject requestObject = wallet.getVerificationRequestObject(
                verification.getVerificationDeeplink()
        );
        final String validPresentation = createEd25519Presentation(credential, requestObject, holderKey);
        final String invalidPresentation = corruptKeyBindingSignature(validPresentation);
        return new InvalidPresentationScenario(verification.getId(), requestObject, invalidPresentation);
    }

    private WalletBatchEntry issueBoundCredential() {
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
        );
        return wallet.collectOffer(toUri(offer.getOfferDeeplink()));
    }

    private ManagementResponse createVerification(final String acceptedIssuerDid) {
        return verifierManager.verificationRequest()
                .acceptedIssuerDid(acceptedIssuerDid)
                .withDCQL()
                .createManagementResponse();
    }

    private Ed25519Issuer createEd25519Issuer() throws JOSEException {
        final URI registryEntry = URI.create(
                "https://%s/api/v1/did/%s".formatted(
                        MockServices.MOCKSERVER_HOST,
                        UUID.randomUUID()
                )
        );
        final OctetKeyPair assertionKey = generateEd25519Key("assert-key-01");
        final OctetKeyPair authenticationKey = generateEd25519Key("auth-key-01");
        final String didLog = DidLogUtil.createDidLog(authenticationKey, assertionKey, registryEntry);
        final String did = DidLogUtil.getDidFromDidLog(didLog);

        mockServices.replaceDidLog(did, didLog);
        return new Ed25519Issuer(did, did + "#assert-key-01", assertionKey);
    }

    private OctetKeyPair generateEd25519Key(final String keyId) throws JOSEException {
        return new OctetKeyPairGenerator(Curve.Ed25519)
                .algorithm(JWSAlgorithm.Ed25519)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(keyId)
                .generate();
    }

    /** Deviation: the Issuer-signed JWT is signed with an Ed25519 key and its DID, not with the ES256 key of the Credential Issuer. */
    private String resignCredentialWithEd25519Issuer(
            final String originalCredential,
            final Ed25519Issuer edIssuer
    ) {
        return SdJwtCredential.parse(originalCredential).resign()
                .signedWithEd25519(edIssuer.signingKey())
                .keyId(edIssuer.keyId())
                .issuer(edIssuer.did())
                .withoutStatus()
                .build()
                .serialize();
    }

    /** Deviation: the credential is bound to an Ed25519 holder key, and the Credential Issuer's own key signs it again. */
    private String replaceHolderKey(
            final String originalCredential,
            final OctetKeyPair holderKey
    ) {
        return SdJwtCredential.parse(originalCredential).resign()
                .signedWith(issuerConfig.getKeyPair())
                .holderKey(holderKey)
                .withoutStatus()
                .build()
                .serialize();
    }

    /** Deviation: the Key Binding JWT is signed with an Ed25519 holder key. */
    private String createEd25519Presentation(
            final String credential,
            final RequestObject requestObject,
            final OctetKeyPair holderKey
    ) {
        final SdJwtCredential presented = SdJwtCredential.parse(credential);
        return presented.presentedWith(
                KeyBindingJwt.forPresentation(presented.withoutKeyBinding(), requestObject.getClientId(), requestObject.getNonce())
                        .signedWithEd25519(holderKey)
                        .build()
        ).serialize();
    }

    private String corruptIssuerSignature(final String credential) {
        return SdJwtCredential.parse(credential).withCorruptedIssuerSignature().serialize();
    }

    private String corruptKeyBindingSignature(final String presentation) {
        return SdJwtCredential.parse(presentation).withCorruptedKeyBindingSignature().serialize();
    }

    private SignedJWT issuerJwt(final String credential) throws ParseException {
        return SignedJWT.parse(SdJwtCredential.parse(credential).issuerSignedJwt());
    }

    private SignedJWT keyBindingJwt(final String presentation) throws ParseException {
        return SignedJWT.parse(SdJwtCredential.parse(presentation).keyBindingJwt().orElseThrow());
    }

    private void replaceIssuedCredential(
            final WalletBatchEntry batchEntry,
            final String credential
    ) {
        batchEntry.replaceIssuedCredential(0, credential);
    }

    private void assertAlgorithms(final JsonNode metadata, final String propertyName) {
        final JsonNode algorithms = metadata.path("vp_formats_supported")
                .path("dc+sd-jwt")
                .path(propertyName);
        assertThat(algorithms.isArray())
                .as("%s must be an array", propertyName)
                .isTrue();
        assertThat(algorithms)
                .extracting(JsonNode::asString)
                .containsExactlyElementsOf(EXPAND_PHASE_ALGORITHMS);
    }

    private String verifierUrl(final String path) {
        return "http://%s:%d%s".formatted(
                verifierContainer.getHost(),
                verifierContainer.getMappedPort(8080),
                path
        );
    }

    private enum Ed25519SignatureTarget {
        ISSUER_SD_JWT(
                VerificationErrorResponseCode.MALFORMED_CREDENTIAL,
                "Failed to extract information from JWT token"
        ),
        KEY_BINDING_JWT(
                VerificationErrorResponseCode.HOLDER_BINDING_MISMATCH,
                "Holder Binding provided does not match the one in the credential"
        );

        private final VerificationErrorResponseCode errorCode;
        private final String signatureFailureMessage;

        Ed25519SignatureTarget(
                final VerificationErrorResponseCode errorCode,
                final String signatureFailureMessage
        ) {
            this.errorCode = errorCode;
            this.signatureFailureMessage = signatureFailureMessage;
        }

        VerificationErrorResponseCode errorCode() {
            return errorCode;
        }

        String signatureFailureMessage() {
            return signatureFailureMessage;
        }
    }

    private record Ed25519Issuer(String did, String keyId, OctetKeyPair signingKey) {
    }

    private record InvalidPresentationScenario(
            UUID verificationId,
            RequestObject requestObject,
            String presentation
    ) {
    }
}
