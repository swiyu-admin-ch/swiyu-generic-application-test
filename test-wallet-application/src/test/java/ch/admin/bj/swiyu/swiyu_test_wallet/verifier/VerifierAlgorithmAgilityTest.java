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
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.registry.DidLogUtil;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;
import tools.jackson.databind.JsonNode;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
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
                        MockServerClientConfig.MOCKSERVER_HOST,
                        UUID.randomUUID()
                )
        );
        final OctetKeyPair assertionKey = generateEd25519Key("assert-key-01");
        final OctetKeyPair authenticationKey = generateEd25519Key("auth-key-01");
        final String didLog = DidLogUtil.createDidLog(authenticationKey, assertionKey, registryEntry);
        final String did = DidLogUtil.getDidFromDidLog(didLog);

        mockServerClientConfig.replaceDidLog(did, didLog);
        return new Ed25519Issuer(did, did + "#assert-key-01", assertionKey);
    }

    private OctetKeyPair generateEd25519Key(final String keyId) throws JOSEException {
        return new OctetKeyPairGenerator(Curve.Ed25519)
                .algorithm(JWSAlgorithm.Ed25519)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(keyId)
                .generate();
    }

    private String resignCredentialWithEd25519Issuer(
            final String originalCredential,
            final Ed25519Issuer edIssuer
    ) throws ParseException, JOSEException {
        final CredentialParts parts = credentialParts(originalCredential);
        final SignedJWT originalJwt = SignedJWT.parse(parts.jwt());
        final JWTClaimsSet claims = new JWTClaimsSet.Builder(originalJwt.getJWTClaimsSet())
                .issuer(edIssuer.did())
                .claim("status", null)
                .build();
        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.Ed25519)
                .type(originalJwt.getHeader().getType())
                .keyID(edIssuer.keyId())
                .build();
        final SignedJWT ed25519Jwt = new SignedJWT(header, claims);
        ed25519Jwt.sign(new Ed25519Signer(edIssuer.signingKey()));
        return ed25519Jwt.serialize() + parts.disclosures();
    }

    private String replaceHolderKey(
            final String originalCredential,
            final OctetKeyPair holderKey
    ) throws ParseException, JOSEException {
        final CredentialParts parts = credentialParts(originalCredential);
        final SignedJWT originalJwt = SignedJWT.parse(parts.jwt());
        final JWTClaimsSet claims = new JWTClaimsSet.Builder(originalJwt.getJWTClaimsSet())
                .claim("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()))
                .claim("status", null)
                .build();
        final SignedJWT issuerJwt = new SignedJWT(originalJwt.getHeader(), claims);
        issuerJwt.sign(ECCryptoSupport.createECDSASigner(issuerConfig.getKeyPair().getPrivate()));
        return issuerJwt.serialize() + parts.disclosures();
    }

    private String createEd25519Presentation(
            final String credential,
            final RequestObject requestObject,
            final OctetKeyPair holderKey
    ) throws JOSEException {
        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.Ed25519)
                .type(new JOSEObjectType("kb+jwt"))
                .build();
        final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("sd_hash", sha256Base64Url(credential))
                .audience(requestObject.getClientId())
                .claim("nonce", requestObject.getNonce())
                .issueTime(new Date())
                .build();
        final SignedJWT keyBindingJwt = new SignedJWT(header, claims);
        keyBindingJwt.sign(new Ed25519Signer(holderKey));
        return credential + keyBindingJwt.serialize();
    }

    private String corruptIssuerSignature(final String credential) {
        final CredentialParts parts = credentialParts(credential);
        return corruptCompactJwsSignature(parts.jwt()) + parts.disclosures();
    }

    private String corruptKeyBindingSignature(final String presentation) {
        final int lastDisclosureSeparator = presentation.lastIndexOf('~');
        assertThat(lastDisclosureSeparator)
                .as("A holder-bound SD-JWT presentation must separate the KB-JWT with '~'")
                .isPositive();
        return presentation.substring(0, lastDisclosureSeparator + 1)
                + corruptCompactJwsSignature(presentation.substring(lastDisclosureSeparator + 1));
    }

    private String corruptCompactJwsSignature(final String jwt) {
        final String[] parts = jwt.split("\\.", -1);
        assertThat(parts).hasSize(3);
        assertThat(parts[2]).isNotEmpty();
        final char replacement = parts[2].charAt(0) == 'A' ? 'B' : 'A';
        parts[2] = replacement + parts[2].substring(1);
        return String.join(".", parts);
    }

    private CredentialParts credentialParts(final String credential) {
        final int disclosureSeparator = credential.indexOf('~');
        assertThat(disclosureSeparator)
                .as("The issued SD-JWT must contain disclosures")
                .isPositive();
        return new CredentialParts(
                credential.substring(0, disclosureSeparator),
                credential.substring(disclosureSeparator)
        );
    }

    private SignedJWT issuerJwt(final String credential) throws ParseException {
        return SignedJWT.parse(credentialParts(credential).jwt());
    }

    private SignedJWT keyBindingJwt(final String presentation) throws ParseException {
        return SignedJWT.parse(presentation.substring(presentation.lastIndexOf('~') + 1));
    }

    private String sha256Base64Url(final String value) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(digest.digest(value.getBytes(StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private void replaceIssuedCredential(
            final WalletBatchEntry batchEntry,
            final String credential
    ) {
        batchEntry.clearIssuedCredentials();
        batchEntry.addIssuedCredential(credential);
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

    private record CredentialParts(String jwt, String disclosures) {
    }

    private record InvalidPresentationScenario(
            UUID verificationId,
            RequestObject requestObject,
            String presentation
    ) {
    }
}
