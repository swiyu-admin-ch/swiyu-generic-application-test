package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlClaimDto;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlQueryDto;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseVerifiers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialClaimsFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JwtSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.UseWallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact.SdJwtCredential;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientResponseException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import static ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialClaimsConstants.*;
import static ch.admin.bj.swiyu.swiyu_test_wallet.mock.MockServices.VERIFIER_CALLBACK_PATH;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.DEFAULT_CREDENTIAL_ID;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.defaultDcqlQuery;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockserver.model.HttpRequest.request;

/**
 * EIDOMNI-1201: only DCQL-selected values cross the Verifier Management API boundary.
 * The business response shape (claim id, otherwise dotted path, mapped to a list) comes from the feature README.
 * OID4VP 1.0 §6.3, §6.4.1 and §7.1.1 define query selection, not this management response format.
 * The Swiss verification profile §8 requires encrypted direct_post.jwt responses.
 * Issuance setup explicitly uses unsigned metadata: the current Issuer exposes only JSON Authorization Server
 * metadata (a known setup limitation against Swiss issuance profile §12.3). Signed metadata is outside this test scope.
 */
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseVerifiers(VerifierVariant.AUDIT_DEFAULTS)
@UseWallet(dpop = true, encryption = true, signedMetadata = false)
@Tag(ReportingTags.UCV_O2)
class VerifierRequestedClaimsE2ETest extends BaseTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String SUBJECT_DATA = "/wallet_response/credential_subject_data";

    static Stream<Arguments> requestedValues() {
        final Map<String, Object> profile = CredentialClaimsFixtures.createBaseProfile();
        return Stream.of(
                Arguments.of("scalar types and falsy values keep their types under mixed ids and paths",
                        List.of(claim("holder", "name"), claim(null, "birth_year"),
                                claim(null, "additional_info_list", 0), claim(null, "additional_info_list", 1),
                                claim(null, "additional_info_list", 2)),
                        Map.of("holder", List.of(DEFAULT_NAME), "birth_year", List.of(DEFAULT_BIRTH_YEAR),
                                "additional_info_list.0", List.of(false), "additional_info_list.1", List.of(0),
                                "additional_info_list.2", List.of(""))),
                Arguments.of("nested leaf excludes siblings", List.of(claim(null, "address", "locality")),
                        Map.of("address.locality", List.of(DEFAULT_LOCALITY))),
                Arguments.of("whole requested object", List.of(claim(null, "address")),
                        Map.of("address", List.of(profile.get("address")))),
                Arguments.of("alias resembling metadata", List.of(claim("iss", "name")),
                        Map.of("iss", List.of(DEFAULT_NAME))),
                Arguments.of("matching value constraint", List.of(claim(null, "name").values(List.of(DEFAULT_NAME))),
                        Map.of("name", List.of(DEFAULT_NAME)))
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("requestedValues")
    @XrayTest(
            key = "EIDOMNI-1484",
            summary = "Business Verifier receives only requested DCQL values when the Wallet overdiscloses",
            description = """
                    Given an issued SD-JWT VC and an encrypted DCQL verification request.
                    When the Wallet deliberately presents every disclosure, including unrequested personal data.
                    Then the Verifier succeeds and its Management API returns exactly the requested values under claim ids or dotted paths, including after a repeated read.
                    Deviation: the Wallet sends unrequested selectively disclosable claims, contrary to OID4VP 1.0 §6.4.
                    Spec: OID4VP 1.0 §6.3, §7.1.1; management filtering and response shape: EIDOMNI-1201 and feature README.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    void businessVerifier_whenWalletOverdiscloses_thenOnlyRequestedValuesAreReturned(
            final String scenario, final List<DcqlClaimDto> claims, final Map<String, Object> expectedValues
    ) {
        // Given: the unrelated additional_info disclosure is present even for a nested or indexed query.
        final WalletBatchEntry credentials = issueCredential();
        final ManagementResponse verification = createVerification(claims);
        final RequestObject request = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = credentials.createPresentationForSdJwtIndex(0, request);
        assertThat(SdJwtCredential.parse(presentation).withoutKeyBinding())
                .as("The Wallet forwards the entire issued credential without selective disclosure")
                .isEqualTo(credentials.getIssuedCredentials().getFirst());
        assertThat(SdJwtCredential.parse(presentation).disclosures())
                .as("The malicious Wallet really includes unrequested additional_info")
                .anySatisfy(disclosure -> assertThat(new Base64URL(disclosure).decodeToString())
                        .contains("\"additional_info\""));

        // When
        wallet.respondToVerification(request, presentation);
        final JsonNode result = readManagement(verification.getId());

        // Then: exact equality detects any extra metadata, sibling, array element or disclosure.
        assertThat(result.path("state").asText())
                .isEqualTo("SUCCESS");
        assertThat(result.at(SUBJECT_DATA))
                .as(scenario)
                .isEqualTo(JSON.valueToTree(Map.of(DEFAULT_CREDENTIAL_ID, expectedValues)));
        assertThat(result.at("/wallet_response/vp_token").isMissingNode()
                || result.at("/wallet_response/vp_token").isNull())
                .as("Production defaults must not expose the unfiltered presentation as an audit token")
                .isTrue();
        assertThat(readManagement(verification.getId()).at(SUBJECT_DATA))
                .isEqualTo(result.at(SUBJECT_DATA));
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() ->
                assertThat(verifierCallbacks(verification.getId()))
                        .as("Exactly one callback for this completed verification")
                        .hasSize(1));
        assertThat(verifierCallbacks(verification.getId()).getFirst().properties())
                .as("The notification contains no credential values or raw presentation")
                .extracting(Map.Entry::getKey)
                .containsExactlyInAnyOrder("verification_id", "timestamp");
    }

    /**
     * Every case sends the complete array. DCQL indexes are zero based: the third element is index 2.
     * Expected lists are literal business results, independent of the Wallet's disclosure selector.
     */
    static Stream<Arguments> requestedArrayValues() {
        final Map<String, Object> numbers = Map.of("favorite_numbers", List.of(1, 2, 3, 4, 5));
        final Map<String, Object> duplicates = Map.of("favorite_numbers", List.of(7, 3, 3, 9));
        final Map<String, Object> matrix = Map.of("favorite_numbers", List.of(
                List.of(101, 102, 103), List.of(201, 202, 203), List.of(301, 302, 303)));
        final Map<String, Object> degreeOne = Map.of("type", "degree-1", "university", "private-campus-1");
        final Map<String, Object> degreeTwo = Map.of("type", "degree-2", "university", "private-campus-2");
        final Map<String, Object> degreeThree = Map.of("type", "degree-3", "university", "private-campus-3");
        final Map<String, Object> degreeFour = Map.of("type", "degree-4", "university", "private-campus-4");
        final Map<String, Object> degrees = Map.of("degrees", List.of(
                degreeOne, Map.of("university", "private-campus-2"), degreeThree, degreeFour));
        final Map<String, Object> objectMatrix = Map.of("favorite_numbers", List.of(
                List.of(degreeOne, degreeTwo, degreeThree), List.of(degreeFour)));
        return Stream.of(
                Arguments.of("third element: Wallet sends [1,2,3,4,5], business receives only 3", numbers,
                        List.of(claim(null, "favorite_numbers", 2)), Map.of("favorite_numbers.2", List.of(3))),
                Arguments.of("first and last valid indexes exclude every middle element", numbers,
                        List.of(claim(null, "favorite_numbers", 0), claim(null, "favorite_numbers", 4)),
                        Map.of("favorite_numbers.0", List.of(1), "favorite_numbers.4", List.of(5))),
                Arguments.of("several nonadjacent indexes with aliases and reversed query order", numbers,
                        List.of(claim("third", "favorite_numbers", 2), claim("first", "favorite_numbers", 0)),
                        Map.of("third", List.of(3), "first", List.of(1))),
                Arguments.of("whole array stays nested whereas wildcard returns individual elements", numbers,
                        List.of(claim(null, "favorite_numbers"), claim(null, "favorite_numbers", null)),
                        Map.of("favorite_numbers", List.of(List.of(1, 2, 3, 4, 5)),
                                "favorite_numbers.null", List.of(1, 2, 3, 4, 5))),
                Arguments.of("single element array keeps its index", Map.of("favorite_numbers", List.of(3)),
                        List.of(claim(null, "favorite_numbers", 0)), Map.of("favorite_numbers.0", List.of(3))),
                Arguments.of("duplicate values do not cause other indexes to be returned", duplicates,
                        List.of(claim(null, "favorite_numbers", 2)), Map.of("favorite_numbers.2", List.of(3))),
                Arguments.of("wildcard preserves duplicate values and their order", duplicates,
                        List.of(claim(null, "favorite_numbers", null)), Map.of("favorite_numbers.null", List.of(7, 3, 3, 9))),
                Arguments.of("third scalar in a heterogeneous array excludes the object and nested array",
                        Map.of("favorite_numbers", List.of("private-first", false, 3,
                                Map.of("secret", "private-object"), List.of("private-nested"))),
                        List.of(claim(null, "favorite_numbers", 2)), Map.of("favorite_numbers.2", List.of(3))),
                // These two prerequisites expose an Issuer/builder defect, before the Verifier receives a response.
                Arguments.of("issuance prerequisite: null before the requested index does not compact the array",
                        Map.of("favorite_numbers", Arrays.asList(null, 2, 3, 4)),
                        List.of(claim(null, "favorite_numbers", 2)), Map.of("favorite_numbers.2", List.of(3))),
                Arguments.of("issuance prerequisite: a requested null is preserved as a JSON null",
                        Map.of("favorite_numbers", Arrays.asList(1, 2, null, 4)),
                        List.of(claim(null, "favorite_numbers", 2)), Map.of("favorite_numbers.2", Arrays.asList((Object) null))),
                Arguments.of("an explicitly requested empty array is an empty JSON array",
                        Map.of("favorite_numbers", List.of()), List.of(claim(null, "favorite_numbers")),
                        Map.of("favorite_numbers", List.of(List.of()))),
                Arguments.of("third element of third nested array excludes every neighboring cell", matrix,
                        List.of(claim(null, "favorite_numbers", 2, 2)), Map.of("favorite_numbers.2.2", List.of(303))),
                Arguments.of("whole row stays nested whereas row wildcard returns its individual elements", matrix,
                        List.of(claim(null, "favorite_numbers", 2), claim(null, "favorite_numbers", 2, null)),
                        Map.of("favorite_numbers.2", List.of(List.of(301, 302, 303)),
                                "favorite_numbers.2.null", List.of(301, 302, 303))),
                Arguments.of("wildcard then index selects only the third column", matrix,
                        List.of(claim(null, "favorite_numbers", null, 2)), Map.of("favorite_numbers.null.2", List.of(103, 203, 303))),
                Arguments.of("two wildcards flatten the selected values in array order", matrix,
                        List.of(claim(null, "favorite_numbers", null, null)),
                        Map.of("favorite_numbers.null.null", List.of(101, 102, 103, 201, 202, 203, 301, 302, 303))),
                Arguments.of("ragged arrays discard rows without the requested third element",
                        Map.of("favorite_numbers", List.of(List.of(101), List.of(201, 202), List.of(301, 302, 303))),
                        List.of(claim(null, "favorite_numbers", null, 2)), Map.of("favorite_numbers.null.2", List.of(303))),
                Arguments.of("third object's type excludes siblings and keeps its index despite an earlier missing property", degrees,
                        List.of(claim(null, "degrees", 2, "type")), Map.of("degrees.2.type", List.of("degree-3"))),
                Arguments.of("whole third object includes its fields but excludes other objects", degrees,
                        List.of(claim(null, "degrees", 2)), Map.of("degrees.2", List.of(degreeThree))),
                Arguments.of("aliased object wildcard skips missing properties and excludes private universities", degrees,
                        List.of(claim("education", "degrees", null, "type")),
                        Map.of("education", List.of("degree-1", "degree-3", "degree-4"))),
                Arguments.of("different fields of different objects stay under their own ids", degrees,
                        List.of(claim("third_type", "degrees", 2, "type"), claim("first_university", "degrees", 0, "university")),
                        Map.of("third_type", List.of("degree-3"), "first_university", List.of("private-campus-1"))),
                Arguments.of("nested object arrays: third column skips a row without that index", objectMatrix,
                        List.of(claim(null, "favorite_numbers", null, 2, "type")),
                        Map.of("favorite_numbers.null.2.type", List.of("degree-3"))),
                Arguments.of("nested object arrays: a single field of one cell excludes siblings", objectMatrix,
                        List.of(claim(null, "favorite_numbers", 0, 2, "type")),
                        Map.of("favorite_numbers.0.2.type", List.of("degree-3"))),
                Arguments.of("nested object arrays: two wildcards select only the requested fields", objectMatrix,
                        List.of(claim(null, "favorite_numbers", null, null, "type")),
                        Map.of("favorite_numbers.null.null.type", List.of("degree-1", "degree-2", "degree-3", "degree-4")))
        );
    }

    @ParameterizedTest(name = "{0}; full arrays sent={1}; business result={3}")
    @MethodSource("requestedArrayValues")
    @XrayTest(
            key = "EIDOMNI-1485",
            summary = "Business Verifier extracts only requested array values when the Wallet sends every array element",
            description = """
                    Given a credential containing complete scalar, heterogeneous, object or nested arrays.
                    When the Wallet sends the entire issued SD-JWT without removing a single disclosure, regardless of the requested indexes or wildcards.
                    Then the Management API returns exactly the selected array values and no other elements, sibling fields, parent containers or metadata.
                    The third element of [1,2,3,4,5] is DCQL index 2 and the business result contains only [3].
                    Deviation: the Wallet overdiscloses unrequested claims and array elements, contrary to OID4VP 1.0 §6.4.
                    Spec: OID4VP 1.0 §7.1, §7.1.1; RFC 9901 §4.2.2; business filtering and output shape: EIDOMNI-1201 and feature README.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    void businessVerifier_whenWalletSendsEntireArrays_thenOnlyRequestedArrayValuesAreReturned(
            final String scenario, final Map<String, Object> fullArrays,
            final List<DcqlClaimDto> claims, final Map<String, Object> expectedValues
    ) {
        // Given: this deliberately bypasses the Wallet's DisclosureSelector for every array scenario.
        final WalletBatchEntry credentials = issueCredential(fullArrays);
        final String issuedCredential = credentials.getIssuedCredentials().getFirst();
        final ManagementResponse verification = createVerification(claims);
        final RequestObject request = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = credentials.createPresentationForSdJwtIndex(0, request);
        final SdJwtCredential sentCredential = SdJwtCredential.parse(presentation);
        assertThat(sentCredential.withoutKeyBinding())
                .as("The Wallet sends the exact issued JWT and every disclosure, including ALL unrequested array elements: %s", fullArrays)
                .isEqualTo(issuedCredential);
        // Exact serialization equality already proves that no disclosure was removed or reordered.
        final List<JsonNode> disclosedClaims = sentCredential.disclosures().stream()
                .map(disclosure -> JSON.readTree(new Base64URL(disclosure).decodeToString()))
                .toList();
        for (final var fullArray : fullArrays.entrySet()) {
            final List<JsonNode> arrayDisclosures = disclosedClaims.stream()
                    .filter(disclosure -> disclosure.size() == 3 && fullArray.getKey().equals(disclosure.get(1).asText()))
                    .map(disclosure -> disclosure.get(2))
                    .toList();
            assertThat(arrayDisclosures)
                    .as("The issued credential actually contains the full array claim %s", fullArray.getKey())
                    .singleElement()
                    .satisfies(array -> assertThat(array.size())
                            .as("The Issuer preserved every position of %s; signed array disclosure=%s", fullArray.getValue(), array)
                            .isEqualTo(((List<?>) fullArray.getValue()).size()));
        }

        // When: the Verifier itself must extract the requested values from the full arrays.
        wallet.respondToVerification(request, presentation);
        final JsonNode result = readManagement(verification.getId());

        // Then: exact JSON equality also rejects extra indexes and fields hidden inside returned objects.
        assertThat(result.path("state").asText())
                .isEqualTo("SUCCESS");
        assertThat(result.at(SUBJECT_DATA))
                .as("%s; Wallet sent %s; Business Verifier must receive only %s", scenario, fullArrays, expectedValues)
                .isEqualTo(JSON.valueToTree(Map.of(DEFAULT_CREDENTIAL_ID, expectedValues)));
        assertThat(readManagement(verification.getId()).at(SUBJECT_DATA))
                .as("Repeated management retrieval cannot expose previously discarded array elements")
                .isEqualTo(result.at(SUBJECT_DATA));
    }

    static Stream<Arguments> unmatchedArrayPaths() {
        return Stream.of(
                Arguments.of("index 5 is outside an array of length 5", List.of(1, 2, 3, 4, 5),
                        claim(null, "favorite_numbers", 5)),
                Arguments.of("index 0 in an empty array", List.of(), claim(null, "favorite_numbers", 0)),
                Arguments.of("wildcard in an empty array", List.of(), claim(null, "favorite_numbers", null)),
                Arguments.of("third element is absent from every nested array", List.of(List.of(1), List.of(2, 3)),
                        claim(null, "favorite_numbers", null, 2))
        );
    }

    @ParameterizedTest(name = "{0}; full array sent={1}")
    @MethodSource("unmatchedArrayPaths")
    @XrayTest(
            key = "EIDOMNI-1486",
            summary = "Verifier rejects an unmatched array path without returning other array elements",
            description = """
                    Given a DCQL path with an out-of-range array index or an empty wildcard selection.
                    When the Wallet deliberately sends the entire credential despite the requested path having no matching element.
                    Then the Verifier rejects the response with HTTP 400, stores FAILED and returns no credential subject data.
                    Deviation: the Wallet presents a credential that cannot satisfy the request, contrary to OID4VP 1.0 §6.4.1.
                    Spec: OID4VP 1.0 §7.1.1 Processing; HTTP 400 is the Verifier API validation contract.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    void verifier_whenRequestedArrayPathMatchesNoElement_thenNoFallbackArrayValuesAreReturned(
            final String scenario, final List<?> fullArray, final DcqlClaimDto claim
    ) {
        // Given: sending extra array values must never substitute for the requested missing element.
        final WalletBatchEntry credentials = issueCredential(Map.of("favorite_numbers", fullArray));
        final ManagementResponse verification = createVerification(List.of(claim));
        final RequestObject request = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = credentials.createPresentationForSdJwtIndex(0, request);
        assertThat(SdJwtCredential.parse(presentation).withoutKeyBinding())
                .as("The Wallet still sends the complete array for this unsatisfied request")
                .isEqualTo(credentials.getIssuedCredentials().getFirst());

        // When
        final HttpClientErrorException error = assertThrows(HttpClientErrorException.class,
                () -> wallet.respondToVerification(request, presentation), scenario);
        final JsonNode result = readManagement(verification.getId());

        // Then
        ApiErrorAssert.assertThat(error)
                .hasStatus(400);
        assertThat(result.path("state").asText())
                .isEqualTo("FAILED");
        assertThat(result.at(SUBJECT_DATA).isMissingNode() || result.at(SUBJECT_DATA).isNull())
                .as("No complete array, neighboring element or partially accepted credential may reach the business")
                .isTrue();
    }

    static Stream<Arguments> requestedMetadata() {
        return Stream.of(
                Arguments.of(List.of()),
                Arguments.of(List.of("iss")),
                Arguments.of(List.of("exp")),
                Arguments.of(List.of("nbf")),
                Arguments.of(List.of("iss", "exp", "nbf", "vct", "cnf", "status"))
        );
    }

    @ParameterizedTest(name = "requested metadata: {0}")
    @MethodSource("requestedMetadata")
    @XrayTest(
            key = "EIDOMNI-1487",
            summary = "Business Verifier receives credential metadata only when explicitly requested in DCQL",
            description = """
                    Given an issued credential containing iss, exp, nbf, vct, cnf and status.
                    When the Wallet deliberately presents every disclosure with valid key binding and encryption.
                    Then the Management API returns the name and exactly the explicitly requested metadata with their original values.
                    Deviation: the Wallet sends unrequested selectively disclosable claims, contrary to OID4VP 1.0 §6.4.
                    Spec: OID4VP 1.0 §6.4.1; metadata filtering is the product requirement EIDOMNI-1201.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    void businessVerifier_whenMetadataIsExplicitlyRequested_thenOnlyThatMetadataIsReturned(final List<String> metadata) {
        // Given: prove metadata exists in the actual issued JWT, so exclusion assertions cannot pass vacuously.
        final WalletBatchEntry credentials = issueCredential();
        final JsonNode issuedPayload = JwtSupport.decodePayloadToJsonNode(
                SdJwtCredential.parse(credentials.getIssuedCredentials().getFirst()).issuerSignedJwt());
        for (final String field : List.of("iss", "exp", "nbf", "vct", "cnf", "status")) {
            assertThat(issuedPayload.hasNonNull(field))
                    .as("Issued credential contains %s", field)
                    .isTrue();
        }
        final List<DcqlClaimDto> claims = Stream.concat(Stream.of(claim(null, "name")),
                metadata.stream().map(field -> claim(null, field))).toList();
        final Map<String, Object> expected = new LinkedHashMap<>();
        expected.put("name", List.of(DEFAULT_NAME));
        metadata.forEach(field -> expected.put(field, List.of(issuedPayload.get(field))));
        final ManagementResponse verification = createVerification(claims);
        final RequestObject request = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = credentials.createPresentationForSdJwtIndex(0, request);
        assertThat(SdJwtCredential.parse(presentation).withoutKeyBinding())
                .as("Even metadata filtering is exercised with the entire credential, including all arrays")
                .isEqualTo(credentials.getIssuedCredentials().getFirst());

        // When
        wallet.respondToVerification(request, presentation);
        final JsonNode result = readManagement(verification.getId());

        // Then
        assertThat(result.path("state").asText())
                .isEqualTo("SUCCESS");
        assertThat(result.at(SUBJECT_DATA))
                .isEqualTo(JSON.valueToTree(Map.of(DEFAULT_CREDENTIAL_ID, expected)));
    }

    @ParameterizedTest(name = "Wallet overdiscloses: {0}")
    @ValueSource(booleans = {false, true})
    @XrayTest(
            key = "EIDOMNI-1488",
            summary = "Business Verifier receives no claim values when the DCQL claims member is absent",
            description = """
                    Given a DCQL Credential Query with no claims member.
                    When the Wallet presents only mandatory JWT content, or deliberately presents every disclosure.
                    Then verification succeeds and the Management API returns an empty object for that credential query.
                    Deviation: in the overdisclosure variant only, the Wallet violates OID4VP 1.0 §6.4.1 by sending optional disclosures.
                    Spec: OID4VP 1.0 §6.4.1; empty business data is required by EIDOMNI-1201.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    void businessVerifier_whenNoClaimsAreRequested_thenNoValuesAreReturned(final boolean overdisclose) {
        // Given
        final WalletBatchEntry credentials = issueCredential();
        final ManagementResponse verification = createVerification(null);
        final RequestObject request = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        assertThat(request.getDcqlQuery().getCredentials().getFirst().getClaims())
                .isNullOrEmpty();
        assertThat(JwtSupport.decodePayloadToJsonNode(wallet.getVerificationDetailSigned(verification.getVerificationDeeplink()))
                .at("/dcql_query/credentials/0").has("claims"))
                .as("The signed Request Object omits claims rather than sending an invalid empty claims array")
                .isFalse();
        final String presentation = overdisclose
                ? credentials.createPresentationForSdJwtIndex(0, request)
                : credentials.createSelectiveDisclosurePresentationForSdJwtIndex(0, request);
        assertThat(SdJwtCredential.parse(presentation).disclosures().isEmpty())
                .isEqualTo(!overdisclose);

        // When
        wallet.respondToVerification(request, presentation);
        final JsonNode result = readManagement(verification.getId());

        // Then
        assertThat(result.path("state").asText())
                .isEqualTo("SUCCESS");
        assertThat(result.at(SUBJECT_DATA))
                .isEqualTo(JSON.valueToTree(Map.of(DEFAULT_CREDENTIAL_ID, Map.of())));
    }

    @ParameterizedTest(name = "reverse query order: {0}")
    @ValueSource(booleans = {false, true})
    @XrayTest(
            key = "EIDOMNI-1489",
            summary = "Business Verifier receives values scoped to each DCQL credential query",
            description = """
                    Given two Credential Queries selecting different claims from the same issued credential and reusing a claim id across queries.
                    When the Wallet presents the same valid presentation with the union of both requested disclosures under both query ids.
                    Then the Management API returns only the claim selected by each query, regardless of query order.
                    Spec: OID4VP 1.0 §6.3, §6.4 allows the union of claims requested in separate queries for the same credential; business filtering: EIDOMNI-1201.
                    """)
    @Tag(ReportingTags.HAPPY_PATH)
    void businessVerifier_whenSameCredentialSatisfiesTwoQueries_thenValuesStayScopedToEachQuery(final boolean reverse) {
        // Given: claim ids need be unique only within each claims array (OID4VP §6.3).
        final WalletBatchEntry credentials = issueCredential();
        final var nameQuery = defaultDcqlQuery(List.of(claim("value", "name")), true)
                .getCredentials().getFirst().id("identity");
        final var birthQuery = defaultDcqlQuery(List.of(claim("value", "birth_year")), true)
                .getCredentials().getFirst().id("birth");
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .encrypted()
                .jwtSecure()
                .dcqlQuery(new DcqlQueryDto().credentials(reverse ? List.of(birthQuery, nameQuery) : List.of(nameQuery, birthQuery)))
                .createManagementResponse();
        final RequestObject request = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = credentials.heldCredential(0).present(request.getClientId(), request.getNonce(),
                List.of(claim(null, "name"), claim(null, "birth_year")));
        final Map<String, Object> payload = Map.of("state", request.getState(), "vp_token",
                Map.of("identity", List.of(presentation), "birth", List.of(presentation)));

        // When
        final var response = wallet.respondToVerificationWithEncryptedPayload(request, JSON.writeValueAsString(payload));
        final JsonNode result = readManagement(verification.getId());

        // Then
        assertThat(response.getStatusCode().value())
                .isEqualTo(200);
        assertThat(result.path("state").asText())
                .isEqualTo("SUCCESS");
        assertThat(result.at(SUBJECT_DATA))
                .isEqualTo(JSON.valueToTree(Map.of(
                        "identity", Map.of("value", List.of(DEFAULT_NAME)),
                        "birth", Map.of("value", List.of(DEFAULT_BIRTH_YEAR)))));
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1490",
            summary = "Verifier accepts distinct DCQL claims when an optional id matches another claim path",
            description = """
                    Given an accepted DCQL request with two distinct paths and one optional claim id matching the other path.
                    When the Wallet presents exactly both requested claims with valid signatures and key binding.
                    Then the Verifier completes successfully rather than rejecting a valid presentation because generated result keys collide.
                    Spec: OID4VP 1.0 §6.3 permits optional ids and requires uniqueness only among explicit ids, §6.4.1 selects both claims; business response collision policy: Unknown.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    void verifier_whenOptionalClaimIdMatchesAnotherPath_thenValidPresentationSucceeds() {
        // Given: no duplicate paths or duplicate explicit ids; the collision exists only in the new output mapping.
        final WalletBatchEntry credentials = issueCredential();
        final ManagementResponse verification = createVerification(List.of(
                claim("birth_year", "name"), claim(null, "birth_year")));
        final RequestObject request = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = credentials.createSelectiveDisclosurePresentationForSdJwtIndex(0, request);

        // When
        final int responseStatus;
        try {
            responseStatus = wallet.respondToVerificationWithEncryptedPayload(request, JSON.writeValueAsString(Map.of(
                    "state", request.getState(), "vp_token", Map.of(DEFAULT_CREDENTIAL_ID, List.of(presentation)))))
                    .getStatusCode().value();
        } catch (RestClientResponseException exception) {
            final JsonNode failedResult = readManagement(verification.getId());
            throw new AssertionError("Valid DCQL presentation returned HTTP " + exception.getStatusCode().value()
                    + "; stored state: " + failedResult.path("state").asText()
                    + "; error: " + failedResult.at("/wallet_response/error_description").asText(), exception);
        }
        final JsonNode result = readManagement(verification.getId());

        // Then: the exact representation of colliding keys needs a product decision; valid verification must not crash.
        assertThat(responseStatus)
                .isEqualTo(200);
        assertThat(result.path("state").asText())
                .isEqualTo("SUCCESS");
    }

    private WalletBatchEntry issueCredential() {
        return issueCredential(Map.of());
    }

    private WalletBatchEntry issueCredential(final Map<String, Object> arrayClaims) {
        final Map<String, Object> subject = CredentialClaimsFixtures.createBaseProfile();
        subject.put("additional_info_list", List.of(false, 0, ""));
        subject.putAll(arrayClaims);
        final Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        // The Issuer accepts seconds or milliseconds. Send strings instead of the generated client's numeric Instants.
        final var offer = restClient.post()
                .uri(issuerConfig.getIssuerServiceUrl() + "/management/api/credentials")
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of(
                        "metadata_credential_supported_id", List.of(CredentialConfigurationFixtures.BOUND_IDENTITY_PROFILE_SD_JWT),
                        "credential_subject_data", subject,
                        "credential_metadata", Map.of("deferred", false),
                        "status_lists", List.of(getCurrentStatusList().getStatusRegistryUrl()),
                        "offer_validity_seconds", 600,
                        "credential_valid_from", now.minus(Duration.ofDays(1)).toString(),
                        "credential_valid_until", now.plus(Duration.ofDays(1)).toString()))
                .retrieve()
                .body(CredentialWithDeeplinkResponse.class);
        return wallet.collectOffer(toUri(offer.getOfferDeeplink()));
    }

    private ManagementResponse createVerification(final List<DcqlClaimDto> claims) {
        return verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .encrypted()
                .jwtSecure()
                .withDCQL(claims)
                .createManagementResponse();
    }

    private JsonNode readManagement(final UUID verificationId) {
        return JSON.readTree(restClient.get()
                .uri(currentVerifier.serviceLocation().getContextualizedUri(
                        URI.create("http://verifier/management/api/verifications/" + verificationId)))
                .retrieve()
                .body(String.class));
    }

    private static DcqlClaimDto claim(final String id, final Object... path) {
        return new DcqlClaimDto().id(id).path(Arrays.asList(path));
    }

    private List<JsonNode> verifierCallbacks(final UUID verificationId) {
        return Arrays.stream(mockServerClient.retrieveRecordedRequests(request().withPath(VERIFIER_CALLBACK_PATH)))
                .map(callback -> JSON.readTree(callback.getBodyAsString()))
                .filter(callback -> verificationId.toString().equals(callback.path("verification_id").asText()))
                .toList();
    }
}
