package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JwtSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.DEFAULT_CREDENTIAL_ID;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.DEFAULT_FORMAT;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.DEFAULT_VCT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierDcqlMultipleCredentialE2ETest extends BaseTest {

    private static final int SUBMITTED_CREDENTIAL_COUNT = 3;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    @Test
    @XrayTest(
            key = "EIDOMNI-1160",
            summary = "Verifier rejects multiple credentials when DCQL multiple is omitted",
            description = """
                    Given a DCQL verification request whose credential query omits the multiple parameter.
                    And a malicious wallet has several credentials matching that query.
                    When the wallet submits three VP tokens for the same credential query id.
                    Then the verifier rejects the presentation because omitted multiple defaults to false.
                    """
    )
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.EDGE_CASE)
    void dcqlPresentation_whenMultipleIsOmittedAndWalletSubmitsThreeCredentials_thenVerifierRejects()
            throws JsonProcessingException {

        // Given
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
        );
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        final ManagementResponse verification = createVerificationWithOmittedMultiple();
        final String requestObjectJwt = wallet.getVerificationDetailSigned(verification.getVerificationDeeplink());
        final JsonNode requestObjectPayload = JwtSupport.decodePayloadToJsonNode(requestObjectJwt);
        final JsonNode credentialQuery = requestObjectPayload.at("/dcql_query/credentials/0");
        final RequestObject requestObject = OBJECT_MAPPER.treeToValue(requestObjectPayload, RequestObject.class);

        assertThat(credentialQuery.get("id").asText())
                .isEqualTo(DEFAULT_CREDENTIAL_ID);
        assertThat(credentialQuery.has("multiple"))
                .as("The DCQL request object must omit multiple so the verifier applies the OID4VP default false")
                .isFalse();
        assertThat(batchEntry.getIssuedCredentials())
                .as("The wallet needs enough credentials to submit a small malicious batch")
                .hasSizeGreaterThanOrEqualTo(SUBMITTED_CREDENTIAL_COUNT);

        final List<String> presentations = IntStream.range(0, SUBMITTED_CREDENTIAL_COUNT)
                .mapToObj(index -> batchEntry.createPresentationForSdJwtIndex(index, requestObject))
                .toList();

        // When
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.respondToVerificationWithVpTokens(requestObject, presentations)
        );

        // Then
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasError("invalid_transaction_data")
                .hasDetail("invalid_presentation_submission")
                .hasErrorDescription("Expected only 1 vp token for VerifiableCredential");
        verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
    }

    private ManagementResponse createVerificationWithOmittedMultiple() {
        final Map<String, Object> request = new LinkedHashMap<>();
        request.put("accepted_issuer_dids", List.of(issuerConfig.getIssuerDid()));
        request.put("jwt_secured_authorization_request", false);
        request.put("response_mode", "direct_post");
        request.put("dcql_query", Map.of("credentials", List.of(dcqlCredentialWithoutMultiple())));

        return restClient.post()
                .uri(currentVerifier.serviceLocation()
                        .getContextualizedUri(URI.create("http://verifier/management/api/verifications")))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .body(request)
                .retrieve()
                .body(ManagementResponse.class);
    }

    private Map<String, Object> dcqlCredentialWithoutMultiple() {
        final Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("id", DEFAULT_CREDENTIAL_ID);
        credential.put("format", DEFAULT_FORMAT);
        credential.put("meta", Map.of("vct_values", List.of(DEFAULT_VCT)));
        credential.put("claims", List.of(Map.of("path", List.of("name"))));
        credential.put("require_cryptographic_holder_binding", true);
        return credential;
    }
}
