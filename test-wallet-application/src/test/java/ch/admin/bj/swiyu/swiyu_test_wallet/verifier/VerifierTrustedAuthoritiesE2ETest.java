package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.UseWallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact.SdJwtCredential;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto.JWESupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto.WalletJwe;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.security.interfaces.ECPublicKey;
import java.sql.SQLException;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.DEFAULT_FORMAT;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.DEFAULT_VCT;
import static ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet.SWIYU_API_VERSION_HEADER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Exercises issuer scoping across the Verifier Management API, persisted DCQL, signed Request Object and encrypted
 * Wallet Authorization Response. The local generated client omits trusted_authorities, so its wire JSON is inspected
 * independently. Swiss verification profile §6.1.1 defines the did authority; OID4VP §8.6 requires query validation.
 */
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseWallet(dpop = true, encryption = true)
class VerifierTrustedAuthoritiesE2ETest extends BaseTest {

    private static final String FIRST_QUERY_ID = "FirstCredential";
    private static final String SECOND_QUERY_ID = "SecondCredential";
    private static final String HOLDER_NAME = "Trusted authorities test holder";
    private static final ObjectMapper JSON = JsonMapper.builder()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    @Test
    @XrayTest(
            key = "EIDOMNI-1435",
            summary = "Verifier preserves explicit authorities and fills only unconstrained credential queries",
            description = """
                    Given three credential queries, two with different explicit did authorities and one without authorities.
                    When the Business Verifier creates a verification with a broader accepted issuer list and the Wallet fetches its signed Request Object.
                    Then database storage and the Request Object preserve both explicit constraints and populate only the unconstrained query.
                    Spec: OID4VP 1.0 §6.1.1; Swiss verification profile §6.1.1; EIDOMNI-1177 fallback requirement.
                    """)
    @Tag(ReportingTags.UCV_M1)
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.HAPPY_PATH)
    void requestObject_whenQueriesHaveMixedAuthorities_thenOnlyMissingAuthoritiesArePopulated()
            throws ParseException, SQLException {
        // Given
        final String issuerDid = issuerConfig.getIssuerDid();
        final String otherDid = swiyuDidVariant(issuerDid);
        final List<Map<String, Object>> firstAuthorities = List.of(didAuthority(List.of(issuerDid)));
        final List<Map<String, Object>> secondAuthorities = List.of(didAuthority(List.of(otherDid)));
        final List<String> acceptedDids = List.of(issuerDid, otherDid);
        final List<Map<String, Object>> queries = List.of(
                credentialQuery(FIRST_QUERY_ID, firstAuthorities),
                credentialQuery(SECOND_QUERY_ID, secondAuthorities),
                credentialQuery("FallbackCredential", null));

        // When
        final ManagementResponse verification = createVerification(acceptedDids, queries);
        final JsonNode persistedDcql = readPersistedDcql(verification.getId());
        final JsonNode requestObject = signedRequestObject(verification);

        // Then
        for (final JsonNode dcql : List.of(persistedDcql, requestObject.path("dcql_query"))) {
            assertThat(dcql.path("credentials").size())
                    .isEqualTo(3);
            assertThat(dcql.at("/credentials/0/trusted_authorities"))
                    .as("The first query must keep its narrower explicit issuer constraint")
                    .isEqualTo(JSON.valueToTree(firstAuthorities));
            assertThat(dcql.at("/credentials/1/trusted_authorities"))
                    .as("The second query must keep its own issuer constraint")
                    .isEqualTo(JSON.valueToTree(secondAuthorities));
            assertThat(dcql.at("/credentials/2/trusted_authorities"))
                    .isEqualTo(JSON.valueToTree(List.of(didAuthority(acceptedDids))));
        }
        assertThat(readManagement(verification.getId()).path("state").asText())
                .isEqualTo("PENDING");
    }

    @ParameterizedTest(name = "accepted_issuer_dids empty: {0}")
    @ValueSource(booleans = {false, true})
    @XrayTest(
            key = "EIDOMNI-1436",
            summary = "Verifier preserves explicit authorities without inventing empty fallback authorities",
            description = """
                    Given one explicitly constrained query and one query without authorities, with accepted_issuer_dids omitted or empty.
                    When the Business Verifier creates a verification and the Wallet fetches its signed Request Object.
                    Then explicit authorities survive persistence and serialization, and the unconstrained query in the Request Object omits trusted_authorities entirely.
                    Spec: OID4VP 1.0 §6.1 and §6.1.1; Swiss verification profile §6.1.1.
                    """)
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.EDGE_CASE)
    void requestObject_whenAcceptedIssuerListIsAbsentOrEmpty_thenExplicitAuthoritiesSurviveWithoutEmptyFallback(
            final boolean emptyList
    ) throws ParseException, SQLException {
        // Given
        final List<Map<String, Object>> authorities = List.of(didAuthority(List.of(issuerConfig.getIssuerDid())));
        final List<Map<String, Object>> queries = List.of(
                credentialQuery(FIRST_QUERY_ID, authorities), credentialQuery(SECOND_QUERY_ID, null));

        // When
        final ManagementResponse verification = createVerification(emptyList ? List.of() : null, queries);
        final JsonNode persistedDcql = readPersistedDcql(verification.getId());
        final JsonNode requestObject = signedRequestObject(verification);

        // Then
        for (final JsonNode dcql : List.of(persistedDcql, requestObject.path("dcql_query"))) {
            assertThat(dcql.at("/credentials/0/trusted_authorities"))
                    .isEqualTo(JSON.valueToTree(authorities));
        }
        final JsonNode storedFallback = persistedDcql.at("/credentials/1/trusted_authorities");
        assertThat(storedFallback.isMissingNode() || storedFallback.isNull())
                .as("Persistence must not invent an empty or non-empty authority constraint")
                .isTrue();
        assertThat(requestObject.at("/dcql_query/credentials/1").has("trusted_authorities"))
                .as("The Request Object must omit an absent constraint, including no null or empty array")
                .isFalse();
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"single", "later value", "later authority", "overlapping authorities"})
    @XrayTest(
            key = "EIDOMNI-1437",
            summary = "Verifier accepts a credential matching any explicit did authority value",
            description = """
                    Given a valid issuer credential and an explicit did constraint whose matching DID is alone, later in values, later in authorities, or repeated across authorities.
                    When the Wallet sends a valid encrypted holder-bound presentation.
                    Then verification succeeds with exactly one credential result and one callback, and repeated management reads preserve that result.
                    Spec: OID4VP 1.0 §6.1.1 and §8.6; Swiss verification profile §6.1.1.
                    """)
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.HAPPY_PATH)
    void presentation_whenIssuerMatchesAnyExplicitAuthority_thenOneCredentialIsAccepted(final String authorityPlacement)
            throws ParseException {
        // Given
        final String issuerDid = issuerConfig.getIssuerDid();
        final String otherDid = swiyuDidVariant(issuerDid);
        final List<Map<String, Object>> authorities = switch (authorityPlacement) {
            case "later value" -> List.of(didAuthority(List.of(otherDid, issuerDid)));
            case "later authority" -> List.of(didAuthority(List.of(otherDid)), didAuthority(List.of(issuerDid)));
            case "overlapping authorities" -> List.of(
                    didAuthority(List.of(issuerDid)), didAuthority(List.of(otherDid, issuerDid)));
            default -> List.of(didAuthority(List.of(issuerDid)));
        };
        final WalletBatchEntry credentials = issueBoundCredential();
        final ManagementResponse verification = createVerification(
                List.of(issuerDid, otherDid), List.of(credentialQuery(FIRST_QUERY_ID, authorities)));
        assertThat(signedRequestObject(verification).at("/dcql_query/credentials/0/trusted_authorities"))
                .isEqualTo(JSON.valueToTree(authorities));
        final RequestObject requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = credentials.createSelectiveDisclosurePresentationForSdJwtIndex(0, requestObject);
        final int callbacksBefore = awaitStableVerifierCallbacks();

        // When
        final ResponseEntity<String> response = wallet.respondToVerificationWithVpTokens(requestObject, List.of(presentation));
        final JsonNode result = readManagement(verification.getId());

        // Then
        assertThat(response.getStatusCode().value())
                .isEqualTo(200);
        assertThat(result.path("state").asText())
                .isEqualTo("SUCCESS");
        assertThat(result.at("/wallet_response/credential_subject_data/" + FIRST_QUERY_ID).size())
                .isEqualTo(1);
        assertThat(result.at("/wallet_response/credential_subject_data/" + FIRST_QUERY_ID + "/holder_name/0").asText())
                .isEqualTo(HOLDER_NAME);
        assertThat(result.at("/credential_evaluation/" + FIRST_QUERY_ID).size())
                .isEqualTo(1);
        assertThat(result.at("/credential_evaluation/" + FIRST_QUERY_ID + "/0/trust_markers/is_trusted").asBoolean())
                .isTrue();
        awaitOneVerifierCallback(callbacksBefore);
        assertThat(awaitStableVerifierCallbacks())
                .isEqualTo(callbacksBefore + 1);
        assertThat(readManagement(verification.getId()))
                .isEqualTo(result);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1438",
            summary = "Verifier accepts two credential queries when each issuer satisfies its own authority constraint",
            description = """
                    Given a valid credential and two required credential queries, one explicitly constrained and one populated from accepted_issuer_dids.
                    When the Wallet sends encrypted holder-bound presentations under both query ids.
                    Then verification succeeds and exposes exactly one credential result under each id with one callback.
                    Spec: OID4VP 1.0 §6.1, §6.4.2 and §8.6; Swiss verification profile §6.1.1.
                    """)
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.HAPPY_PATH)
    void presentation_whenBothQueriesMatchTheirOwnAuthorities_thenBothCredentialResultsAreAccepted() {
        // Given
        final String issuerDid = issuerConfig.getIssuerDid();
        final WalletBatchEntry credentials = issueBoundCredential();
        final ManagementResponse verification = createVerification(List.of(issuerDid), List.of(
                credentialQuery(FIRST_QUERY_ID, List.of(didAuthority(List.of(issuerDid)))),
                credentialQuery(SECOND_QUERY_ID, null)));
        final RequestObject requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = credentials.createSelectiveDisclosurePresentationForSdJwtIndex(0, requestObject);
        final int callbacksBefore = awaitStableVerifierCallbacks();

        // When
        final ResponseEntity<String> response = postEncryptedPresentations(requestObject, Map.of(
                FIRST_QUERY_ID, List.of(presentation), SECOND_QUERY_ID, List.of(presentation)));
        final ManagementResponse result = verifierManager.getVerificationById(verification.getId());

        // Then
        assertThat(response.getStatusCode().value())
                .isEqualTo(200);
        assertThat(result.getState().getValue())
                .isEqualTo("SUCCESS");
        assertThat(result.getWalletResponse().getCredentialSubjectData())
                .containsOnlyKeys(FIRST_QUERY_ID, SECOND_QUERY_ID);
        assertThat(result.getCredentialEvaluation())
                .containsOnlyKeys(FIRST_QUERY_ID, SECOND_QUERY_ID);
        for (final String queryId : List.of(FIRST_QUERY_ID, SECOND_QUERY_ID)) {
            final JsonNode subjectData = JSON.valueToTree(result.getWalletResponse().getCredentialSubjectData().get(queryId));
            assertThat(subjectData.size())
                    .isEqualTo(1);
            assertThat(subjectData.at("/holder_name/0").asText())
                    .isEqualTo(HOLDER_NAME);
            assertThat(subjectData.has("annual_salary"))
                    .as("The Wallet discloses only the requested name claim")
                    .isFalse();
            assertThat(subjectData.has("signature_image"))
                    .isFalse();
            assertThat(result.getCredentialEvaluation().get(queryId))
                    .hasSize(1);
        }
        awaitOneVerifierCallback(callbacksBefore);
        assertThat(awaitStableVerifierCallbacks())
                .isEqualTo(callbacksBefore + 1);
    }

    @ParameterizedTest(name = "restricted query at index {0}")
    @ValueSource(ints = {0, 1})
    @XrayTest(
            key = "EIDOMNI-1439",
            summary = "Verifier rejects a globally accepted issuer that violates one credential query authority",
            description = """
                    Given two required credential queries and a globally accepted issuer excluded by one query's explicit did authority.
                    When a malicious Wallet submits valid encrypted holder-bound presentations from that issuer under both ids.
                    Then the Verifier rejects the whole response with invalid_presentation_submission naming the restricted query, persists FAILED, exposes no accepted claims and emits one callback.
                    Deviation: the Wallet deliberately ignores one query's trusted_authorities constraint; all signatures and holder binding remain valid.
                    Spec: OID4VP 1.0 §6.1, §6.4.2 and §8.6; Swiss verification profile §6.1.1.
                    """)
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.EDGE_CASE)
    void presentation_whenMaliciousWalletIgnoresOneQueryAuthority_thenGlobalAcceptanceCannotBypassIt(
            final int restrictedIndex
    ) {
        // Given
        final String issuerDid = issuerConfig.getIssuerDid();
        final String otherDid = swiyuDidVariant(issuerDid);
        final String restrictedId = restrictedIndex == 0 ? FIRST_QUERY_ID : SECOND_QUERY_ID;
        final List<Map<String, Object>> restrictedAuthorities = List.of(didAuthority(List.of(otherDid)));
        final WalletBatchEntry credentials = issueBoundCredential();
        final ManagementResponse verification = createVerification(List.of(issuerDid, otherDid), List.of(
                credentialQuery(FIRST_QUERY_ID, restrictedIndex == 0 ? restrictedAuthorities : null),
                credentialQuery(SECOND_QUERY_ID, restrictedIndex == 1 ? restrictedAuthorities : null)));
        final RequestObject requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = credentials.createSelectiveDisclosurePresentationForSdJwtIndex(0, requestObject);
        final int callbacksBefore = awaitStableVerifierCallbacks();

        // When
        final HttpClientErrorException error = assertThrows(HttpClientErrorException.class,
                () -> postEncryptedPresentations(requestObject, Map.of(
                        FIRST_QUERY_ID, List.of(presentation), SECOND_QUERY_ID, List.of(presentation))));
        final JsonNode result = readManagement(verification.getId());

        // Then
        ApiErrorAssert.assertThat(error)
                .hasStatus(400)
                .hasError("invalid_transaction_data")
                .hasDetail("invalid_presentation_submission")
                .hasErrorCode("invalid_presentation_submission")
                .hasErrorDescription("No matching SD-JWT for requested credential id " + restrictedId);
        assertThat(result.path("state").asText())
                .isEqualTo("FAILED");
        assertThat(result.at("/wallet_response/error_code").asText())
                .isEqualTo("invalid_presentation_submission");
        assertThat(result.at("/wallet_response/credential_subject_data").isMissingNode())
                .as("A response failing one required query must not expose claims from another query")
                .isTrue();
        assertThat(result.path("credential_evaluation").size())
                .as("No partially successful credential evaluation may escape the failed response")
                .isZero();
        awaitOneVerifierCallback(callbacksBefore);
        assertThat(awaitStableVerifierCallbacks())
                .isEqualTo(callbacksBefore + 1);
    }

    @ParameterizedTest(name = "query accepts signing DID: {0}")
    @ValueSource(booleans = {true, false})
    @XrayTest(
            key = "EIDOMNI-1440",
            summary = "Verifier applies explicit did authorities to the signing kid and ignores conflicting iss",
            description = """
                    Given a valid credential whose signed iss names another DID while kid identifies its actual issuer, and both DIDs are globally accepted.
                    When the Wallet presents it to a query permitting either the signing DID or only the iss DID.
                    Then the signing DID determines success or HTTP 400 invalid_presentation_submission, with one callback and no accepted claims on failure.
                    Deviation: in the rejection variant the Wallet deliberately selects by iss and ignores the constraint on the signing DID.
                    Spec: Swiss anchor profile, JWT Validation with cryptographic keys from DIDs, requires trust checks on kid's DID and requires iss to be ignored; OID4VP 1.0 §8.6.
                    """)
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.EDGE_CASE)
    void presentation_whenIssuerClaimConflictsWithSigningDid_thenExplicitAuthorityDecisionUsesKid(
            final boolean acceptsSigningDid
    ) throws ParseException, JOSEException {
        // Given
        final String signingDid = issuerConfig.getIssuerDid();
        final String claimedDid = swiyuDidVariant(signingDid);
        final WalletBatchEntry credentials = issueBoundCredential();
        final String credential = SdJwtCredential.parse(credentials.getVerifiableCredential(0)).resign()
                .signedWith(issuerConfig.getKeyPair())
                .keyId(issuerConfig.getIssuerAssertKeyId())
                .issuer(claimedDid)
                .build()
                .serialize();
        credentials.replaceIssuedCredential(0, credential);
        final SignedJWT issuerJwt = SignedJWT.parse(SdJwtCredential.parse(credential).issuerSignedJwt());
        assertThat(issuerJwt.getJWTClaimsSet().getIssuer())
                .isEqualTo(claimedDid);
        assertThat(issuerJwt.getHeader().getKeyID())
                .isEqualTo(issuerConfig.getIssuerAssertKeyId());
        assertThat(issuerJwt.verify(new ECDSAVerifier((ECPublicKey) issuerConfig.getKeyPair().getPublic())))
                .as("The conflicting iss must not invalidate the signature or hide the issuer scoping decision")
                .isTrue();
        final String allowedDid = acceptsSigningDid ? signingDid : claimedDid;
        final ManagementResponse verification = createVerification(List.of(signingDid, claimedDid), List.of(
                credentialQuery(FIRST_QUERY_ID, List.of(didAuthority(List.of(allowedDid))))));
        final RequestObject requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = credentials.createSelectiveDisclosurePresentationForSdJwtIndex(0, requestObject);
        final int callbacksBefore = awaitStableVerifierCallbacks();

        // When / Then
        if (acceptsSigningDid) {
            final ResponseEntity<String> response = wallet.respondToVerificationWithVpTokens(requestObject, List.of(presentation));
            assertThat(response.getStatusCode().value())
                    .isEqualTo(200);
            final JsonNode result = readManagement(verification.getId());
            assertThat(result.path("state").asText())
                    .isEqualTo("SUCCESS");
            assertThat(result.at("/wallet_response/credential_subject_data/" + FIRST_QUERY_ID + "/holder_name/0").asText())
                    .isEqualTo(HOLDER_NAME);
        } else {
            final HttpClientErrorException error = assertThrows(HttpClientErrorException.class,
                    () -> wallet.respondToVerificationWithVpTokens(requestObject, List.of(presentation)));
            ApiErrorAssert.assertThat(error)
                    .hasStatus(400)
                    .hasError("invalid_transaction_data")
                    .hasDetail("invalid_presentation_submission")
                    .hasErrorDescription("No matching SD-JWT for requested credential id " + FIRST_QUERY_ID);
            final JsonNode result = readManagement(verification.getId());
            assertThat(result.path("state").asText())
                    .isEqualTo("FAILED");
            assertThat(result.at("/wallet_response/credential_subject_data").isMissingNode())
                    .isTrue();
        }
        awaitOneVerifierCallback(callbacksBefore);
        assertThat(awaitStableVerifierCallbacks())
                .isEqualTo(callbacksBefore + 1);
    }

    private WalletBatchEntry issueBoundCredential() {
        final Map<String, Object> subject = CredentialSubjectFixtures.mandatoryClaimsEmployeeProfile();
        subject.put("name", HOLDER_NAME);
        final var offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT, subject);
        return wallet.collectOffer(toUri(offer.getOfferDeeplink()));
    }

    private static Map<String, Object> didAuthority(final List<String> dids) {
        return Map.of("type", "did", "values", dids);
    }

    private static Map<String, Object> credentialQuery(final String id, final List<Map<String, Object>> authorities) {
        final Map<String, Object> query = new LinkedHashMap<>();
        query.put("id", id);
        query.put("format", DEFAULT_FORMAT);
        query.put("meta", Map.of("vct_values", List.of(DEFAULT_VCT)));
        query.put("claims", List.of(Map.of("id", "holder_name", "path", List.of("name"))));
        query.put("require_cryptographic_holder_binding", true);
        if (authorities != null) {
            query.put("trusted_authorities", authorities);
        }
        return query;
    }

    private static Map<String, Object> managementRequest(
            final List<String> acceptedDids, final List<Map<String, Object>> queries
    ) {
        final Map<String, Object> request = new LinkedHashMap<>();
        request.put("jwt_secured_authorization_request", true);
        request.put("response_mode", "direct_post.jwt");
        request.put("dcql_query", Map.of("credentials", queries));
        if (acceptedDids != null) {
            request.put("accepted_issuer_dids", acceptedDids);
        }
        return request;
    }

    private ManagementResponse createVerification(final List<String> acceptedDids, final List<Map<String, Object>> queries) {
        return JSON.treeToValue(postManagementRequest(managementRequest(acceptedDids, queries)), ManagementResponse.class);
    }

    private JsonNode postManagementRequest(final Map<String, Object> request) {
        return JSON.readTree(restClient.post()
                .uri(currentVerifier.serviceUrl() + "/management/api/verifications")
                .contentType(MediaType.APPLICATION_JSON)
                .body(request)
                .retrieve()
                .body(String.class));
    }

    private JsonNode readManagement(final UUID id) {
        return JSON.readTree(restClient.get()
                .uri(currentVerifier.serviceUrl() + "/management/api/verifications/" + id)
                .retrieve()
                .body(String.class));
    }

    /** Management responses omit the DCQL query; read its persisted JSON without the generated DTO. */
    private JsonNode readPersistedDcql(final UUID id) throws SQLException {
        final String sql = "SELECT dcql_query FROM " + currentVerifier.imageConfig().getDbSchema() + ".management WHERE id = ?";
        try (final var statement = connection.prepareStatement(sql)) {
            statement.setObject(1, id);
            try (final var row = statement.executeQuery()) {
                if (!row.next()) {
                    throw new IllegalStateException("No persisted verification for " + id);
                }
                return JSON.readTree(row.getString("dcql_query"));
            }
        }
    }

    private JsonNode signedRequestObject(final ManagementResponse verification) throws ParseException {
        return JSON.valueToTree(SignedJWT.parse(wallet.getVerificationDetailSigned(verification.getVerificationDeeplink()))
                .getJWTClaimsSet().getClaims());
    }

    /** Sends both query ids; the existing Wallet client currently serializes only its first credential query. */
    private ResponseEntity<String> postEncryptedPresentations(
            final RequestObject requestObject, final Map<String, List<String>> presentations
    ) {
        final Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("vp_token", presentations);
        if (requestObject.getState() != null) {
            payload.put("state", requestObject.getState());
        }
        final String encryptedResponse = WalletJwe.encrypt(JSON.writeValueAsString(payload),
                JWESupport.toECKey(requestObject.getClientMetadata().getJwks().getKeys().getFirst()));
        final var form = new LinkedMultiValueMap<String, Object>();
        form.add("response", encryptedResponse);
        return restClient.post()
                .uri(currentVerifier.serviceLocation().getContextualizedUri(toUri(requestObject.getResponseUri())))
                .header(SWIYU_API_VERSION_HEADER, SwiyuApiVersionConfig.V1.getValue())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .toEntity(String.class);
    }
}
