package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.TrustAnchor;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseVerifiers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.mock.MockServices;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseVerifiers({VerifierVariant.DEFAULT, VerifierVariant.AUDIT_DEFAULTS, VerifierVariant.AUDIT_DISABLED,
        VerifierVariant.AUDIT_VP_TOKEN_ONLY, VerifierVariant.AUDIT_EVALUATION_ONLY})
@DisableIfImageTag(
        verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
        reason = "Configurable management audit information requires EIDOMNI-1321"
)
class VerifierAuditInformationE2ETest extends BaseTest {

    private static final String QUERY_ID = "EmployeeHistory";

    static Stream<Arguments> businessOutcomes() {
        return Arrays.stream(AuditMode.values())
                .flatMap(mode -> Stream.of("VALID", "SUSPENDED", "REVOKED", "UNTRUSTED")
                        .map(outcome -> Arguments.of(mode, outcome)));
    }

    @ParameterizedTest(name = "{0}: credential with {1}")
    @MethodSource("businessOutcomes")
    @XrayTest(
            key = "EIDOMNI-1321",
            summary = "Audit flags filter management JSON without changing credential status or trust decisions",
            description = """
                    Given an issued credential and a DCQL query, with production defaults,
                    all flags disabled, each audit field enabled separately, or all fields enabled.
                    When the wallet presents a valid, suspended or revoked credential, or a credential
                    whose issuer is not trusted by the requested anchor.
                    Then the management JSON omits disabled fields entirely, preserves requested claims when enabled,
                    and exposes tokens and evaluations under the exact query id only when configured. The decision and callback remain
                    correct, and repeated management reads preserve the result.
                    """
    )
    @Tag(ReportingTags.UCV_M3)
    @Tag(ReportingTags.EDGE_CASE)
    void businessResult_whenAuditConfigurationChanges_thenOnlyConfiguredFieldsAreReturned(
            final AuditMode mode,
            final String outcome
    ) {
        // Given
        useVerifier(verifier(mode.variant));
        final var claims = CredentialSubjectFixtures.completeEmployeeProfile();
        final String[] undisclosedClaims = claims.keySet().stream()
                .filter(claim -> !"name".equals(claim))
                .toArray(String[]::new);
        final var offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT, claims);
        final var batch = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final int credentialStatus = switch (outcome) {
            case "SUSPENDED" -> 2;
            case "REVOKED" -> 1;
            default -> 0;
        };
        if (credentialStatus != 0) {
            issuerManager.updateState(offer.getManagementId(),
                    UpdateCredentialStatusRequestType.valueOf(outcome));
        }
        final boolean trusted = !"UNTRUSTED".equals(outcome);
        final var request = verifierManager.verificationRequest();
        if (trusted) {
            request.acceptedIssuerDid(issuerConfig.getIssuerDid());
        } else {
            request.trustAnchor(new TrustAnchor()
                    .did(verifierConfig.getVerifierDid())
                    .trustRegistryUri("https://" + MockServices.MOCKSERVER_HOST + "/untrusted"));
        }
        request.getRequest().getDcqlQuery().getCredentials().getFirst().id(QUERY_ID);
        final var verification = request.createManagementResponse();
        final var requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final var presentations = List.of(batch.createSelectiveDisclosurePresentationForSdJwtIndex(0, requestObject));
        final int callbacksBefore = awaitStableVerifierCallbacks();

        // When
        final var submission = wallet.respondToVerificationWithVpTokens(requestObject, presentations);
        final var response = restClient.get()
                .uri(currentVerifier.serviceUrl() + "/management/api/verifications/" + verification.getId())
                .retrieve()
                .toEntity(String.class);

        // Then: inspect wire JSON, since generated DTOs cannot distinguish missing fields from null.
        assertThat(submission.getStatusCode().value())
                .isEqualTo(200);
        assertThat(response.getStatusCode().value())
                .isEqualTo(200);
        assertThat(response.getHeaders().getContentType())
                .isNotNull()
                .matches(MediaType.APPLICATION_JSON::isCompatibleWith);
        final JsonObject result = JsonParser.parseString(response.getBody()).getAsJsonObject();
        assertThat(result.get("id").getAsString())
                .isEqualTo(verification.getId().toString());
        assertThat(result.get("state").getAsString())
                .isEqualTo(credentialStatus == 0 && trusted ? "SUCCESS" : "FAILED");
        final JsonObject walletResult = result.getAsJsonObject("wallet_response");
        assertThat(walletResult.keySet())
                .doesNotContain("error_code", "error_description");
        assertThat(walletResult.has("credential_subject_data"))
                .isEqualTo(mode.subjectData);
        assertThat(walletResult.has("vp_token"))
                .isEqualTo(mode.vpToken);
        assertThat(result.has("credential_evaluation"))
                .isEqualTo(mode.evaluation);
        assertThat(result.has("credential_evaluations"))
                .as("The current OpenAPI contract uses the singular credential_evaluation")
                .isFalse();
        if (mode.subjectData) {
            final var subjects = walletResult.getAsJsonObject("credential_subject_data");
            assertThat(subjects.keySet())
                    .containsExactly(QUERY_ID);
            final var credentials = subjects.getAsJsonArray(QUERY_ID);
            assertThat(credentials.size())
                    .isEqualTo(1);
            assertThat(credentials.get(0).getAsJsonObject().keySet())
                    .contains("name")
                    .doesNotContain(undisclosedClaims);
            assertThat(credentials.get(0).getAsJsonObject().get("name").getAsString())
                    .isEqualTo(claims.get("name"));
        }
        if (mode.vpToken) {
            final var tokens = walletResult.getAsJsonObject("vp_token");
            assertThat(tokens.keySet())
                    .containsExactly(QUERY_ID);
            assertThat(tokens.getAsJsonArray(QUERY_ID).asList())
                    .extracting(token -> token.getAsString())
                    .containsExactlyElementsOf(presentations);
        }
        if (mode.evaluation) {
            final var evaluations = result.getAsJsonObject("credential_evaluation");
            assertThat(evaluations.keySet())
                    .containsExactly(QUERY_ID);
            assertThat(evaluations.getAsJsonArray(QUERY_ID).size())
                    .isEqualTo(1);
            final var evaluation = evaluations.getAsJsonArray(QUERY_ID).get(0).getAsJsonObject();
            final var status = evaluation.getAsJsonObject("credential_status");
            assertThat(status.get("status").getAsInt())
                    .isEqualTo(credentialStatus);
            assertThat(status.get("valid").getAsBoolean())
                    .isEqualTo(credentialStatus == 0);
            assertThat(evaluation.getAsJsonObject("trust_markers").get("is_trusted").getAsBoolean())
                    .isEqualTo(trusted);
        }
        awaitOneVerifierCallback(callbacksBefore);
        final String repeatedResponse = restClient.get()
                .uri(currentVerifier.serviceUrl() + "/management/api/verifications/" + verification.getId())
                .retrieve()
                .body(String.class);
        assertThat(JsonParser.parseString(repeatedResponse))
                .isEqualTo(result);
        assertThat(countVerifierCallbacks())
                .isEqualTo(callbacksBefore + 1);
    }

    @ParameterizedTest(name = "{0}: invalid issuer signature")
    @EnumSource(AuditMode.class)
    @XrayTest(
            key = "EIDOMNI-1321",
            summary = "Audit configuration never exposes unverified subject data after an invalid signature",
            description = """
                    Given an issued credential whose issuer signature is deliberately corrupted by the wallet.
                    When the wallet submits a holder-bound presentation under each audit configuration.
                    Then verification fails with HTTP 400, management preserves the error but exposes no unverified
                    subject data or successful evaluations. Rejected tokens are not persisted, even with audit enabled.
                    """
    )
    @Tag(ReportingTags.UCV_M3)
    @Tag(ReportingTags.EDGE_CASE)
    void invalidSignature_withAnyAuditConfiguration_thenFailsWithoutUnverifiedClaims(final AuditMode mode) {
        // Given: the malicious wallet changes only the issuer signature.
        useVerifier(verifier(mode.variant));
        final var offer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final var batch = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final String credential = batch.getVerifiableCredential(0);
        final int signatureStart = credential.indexOf('.', credential.indexOf('.') + 1) + 1;
        final char replacement = credential.charAt(signatureStart) == 'A' ? 'B' : 'A';
        batch.clearIssuedCredentials();
        batch.addIssuedCredential(credential.substring(0, signatureStart) + replacement
                + credential.substring(signatureStart + 1));
        final var verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .createManagementResponse();
        final var requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = batch.createPresentationForSdJwtIndex(0, requestObject);
        final int callbacksBefore = awaitStableVerifierCallbacks();

        // When
        final var failure = assertThrows(HttpClientErrorException.class,
                () -> wallet.respondToVerification(requestObject, presentation));
        final String response = restClient.get()
                .uri(currentVerifier.serviceUrl() + "/management/api/verifications/" + verification.getId())
                .retrieve()
                .body(String.class);

        // Then
        assertThat(failure.getStatusCode().value())
                .isEqualTo(400);
        final JsonObject result = JsonParser.parseString(response).getAsJsonObject();
        assertThat(result.get("state").getAsString())
                .isEqualTo("FAILED");
        final var walletResult = result.getAsJsonObject("wallet_response");
        assertThat(walletResult.get("error_code").getAsString())
                .isEqualTo("malformed_credential");
        assertThat(walletResult.get("error_description").getAsString())
                .isNotBlank();
        assertThat(walletResult.has("credential_subject_data"))
                .isFalse();
        assertThat(walletResult.has("vp_token"))
                .as("Cryptographically rejected tokens are not persisted by the verifier")
                .isFalse();
        assertThat(result.has("credential_evaluation"))
                .isEqualTo(mode.evaluation);
        if (mode.evaluation) {
            assertThat(result.getAsJsonObject("credential_evaluation").keySet())
                    .isEmpty();
        }
        awaitOneVerifierCallback(callbacksBefore);
    }

    private enum AuditMode {
        PRODUCTION_DEFAULTS(VerifierVariant.AUDIT_DEFAULTS, false, true, false),
        DISABLED(VerifierVariant.AUDIT_DISABLED, false, false, false),
        VP_TOKEN_ONLY(VerifierVariant.AUDIT_VP_TOKEN_ONLY, true, false, false),
        EVALUATION_ONLY(VerifierVariant.AUDIT_EVALUATION_ONLY, false, false, true),
        ALL_ENABLED(VerifierVariant.DEFAULT, true, true, true);

        private final VerifierVariant variant;
        private final boolean vpToken;
        private final boolean subjectData;
        private final boolean evaluation;

        AuditMode(final VerifierVariant variant, final boolean vpToken, final boolean subjectData,
                  final boolean evaluation) {
            this.variant = variant;
            this.vpToken = vpToken;
            this.subjectData = subjectData;
            this.evaluation = evaluation;
        }
    }
}
