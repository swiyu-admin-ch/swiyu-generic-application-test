package ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.TrustConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.support.TestConstants;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockserver.model.HttpRequest;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class Tp2TrustRegistryMockSupportTest {

    private static final String TRUST_DID =
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did";
    private static final String ISSUER_DID =
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA2:identifier.admin.ch:api:v1:did";
    private static final String PROTECTED_VCT = TestConstants.ISSUER_URL + "/oid4vci/vct/my-vct-v01";

    private Tp2TrustRegistryStatementFactory statementFactory;
    private Tp2MockServerResponseFactory responseFactory;
    private IssuerConfig issuerConfig;
    private TrustConfig trustConfig;

    @BeforeEach
    void setUp() {
        trustConfig = buildTrustConfig();
        issuerConfig = buildIssuerConfig();
        statementFactory = new Tp2TrustRegistryStatementFactory(issuerConfig, trustConfig);
        responseFactory = new Tp2MockServerResponseFactory(new ObjectMapper().findAndRegisterModules());
    }

    @Test
    void identityTrustStatement_whenBuilt_thenContainsExpectedTp2Metadata() throws ParseException {
        SignedJWT statement = SignedJWT.parse(statementFactory.buildIdentityTrustStatement(issuerConfig.getIssuerDid()));

        assertThat(statement.getHeader().getType().toString()).isEqualTo("swiyu-identity-trust-statement+jwt");
        assertThat(statement.getHeader().getCustomParam("profile_version"))
                .isEqualTo(Tp2TrustRegistryStatementFactory.TP2_PROFILE_VERSION);
        assertThat(statement.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
        assertThat(statement.getHeader().getKeyID()).isEqualTo(trustConfig.getTrustAssertKeyId());
        assertThat(statement.getJWTClaimsSet().getIssuer()).isNull();
        assertThat(statement.getJWTClaimsSet().getJWTID()).satisfies(this::assertUuidV4);
        assertThat(statement.getJWTClaimsSet().getIssueTime()).isNotNull();
        assertThat(statement.getJWTClaimsSet().getNotBeforeTime()).isNotNull();
        assertThat(statement.getJWTClaimsSet().getExpirationTime()).isNotNull();
        assertThat(statement.getJWTClaimsSet().getSubject()).isEqualTo(issuerConfig.getIssuerDid());
        assertThat(statement.getJWTClaimsSet().getStringClaim("entity_name")).isEqualTo("Mock TP2 Issuer");
        assertThat(statement.getJWTClaimsSet().getJSONObjectClaim("status"))
                .containsKey("status_list");
    }

    @Test
    void identityTrustStatement_whenRebuiltForSameSubject_thenUsesNewStatementIdentifier() throws ParseException {
        SignedJWT first = SignedJWT.parse(statementFactory.buildIdentityTrustStatement(issuerConfig.getIssuerDid()));
        SignedJWT second = SignedJWT.parse(statementFactory.buildIdentityTrustStatement(issuerConfig.getIssuerDid()));

        assertThat(first.getJWTClaimsSet().getJWTID()).satisfies(this::assertUuidV4);
        assertThat(second.getJWTClaimsSet().getJWTID())
                .satisfies(this::assertUuidV4)
                .isNotEqualTo(first.getJWTClaimsSet().getJWTID());
    }

    @Test
    void protectedIssuanceAuthorization_whenBuilt_thenContainsAuthorizedVctValues() throws ParseException {
        SignedJWT statement = SignedJWT.parse(
                statementFactory.buildProtectedIssuanceAuthorizationStatement(
                        issuerConfig.getIssuerDid(),
                        statementFactory.protectedIssuanceAuthorizationJti()
                )
        );

        @SuppressWarnings("unchecked")
        Map<String, Object> canIssue = (Map<String, Object>) statement.getJWTClaimsSet().getClaim("can_issue");

        assertThat(canIssue)
                .containsEntry("vct", PROTECTED_VCT)
                .containsEntry("vct_name", "Bound Example SD-JWT VC");
        assertProtectedVctUrl((String) canIssue.get("vct"));
    }

    @Test
    void identityTrustStatements_whenNoSubjectRequested_thenReturnIssuerAndVerifierStatements() {
        List<String> statements = statementFactory.buildIdentityTrustStatements(null);

        assertThat(statements).hasSize(2);
    }

    @Test
    void identityTrustStatements_whenUnknownSubjectRequested_thenReturnEmptyList() {
        List<String> statements = statementFactory.buildIdentityTrustStatements("did:tdw:QmUnknown:identifier.admin.ch:api:v1:did");

        assertThat(statements).isEmpty();
    }

    @Test
    void verificationQueryPublicStatementRegistration_whenValidPayload_thenBuildsSignedVqPs() throws ParseException {
        SignedJWT statement = SignedJWT.parse(
                statementFactory.buildVerificationQueryPublicStatementFromRegistration(tmsRegistrationRequest())
        );

        assertThat(statement.getHeader().getType().toString())
                .isEqualTo("swiyu-verification-query-public-statement+jwt");
        assertThat(statement.getHeader().getCustomParam("profile_version"))
                .isEqualTo(Tp2TrustRegistryStatementFactory.TP2_PROFILE_VERSION);
        assertThat(statement.getJWTClaimsSet().getSubject()).isEqualTo(Tp2TrustRegistryStatementFactory.TP2_DEFAULT_VERIFIER_SUBJECT);
        assertThat(statement.getJWTClaimsSet().getJWTID()).satisfies(this::assertUuidV4);
        assertThat(statement.getJWTClaimsSet().getStringClaim("purpose_name#en")).isEqualTo("Age verification");

        @SuppressWarnings("unchecked")
        Map<String, Object> request = (Map<String, Object>) statement.getJWTClaimsSet().getClaim("request");
        @SuppressWarnings("unchecked")
        Map<String, Object> query = (Map<String, Object>) request.get("query");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) query.get("credentials");
        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) credentials.getFirst().get("meta");
        assertThat(request).containsEntry("type", "DCQL")
                .containsEntry("scope", "com.example.age_verification_presentation");
        assertProtectedVctValues(meta.get("vct_values"));
    }

    @Test
    void verificationQueryPublicStatementRegistration_whenDcqlHasNoVctValues_thenRejectsPayload() {
        Map<String, Object> request = tmsRegistrationRequest();
        @SuppressWarnings("unchecked")
        Map<String, Object> query = (Map<String, Object>) request.get("query");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) query.get("credentials");
        credentials.getFirst().put("meta", Map.of("vct_values", List.of()));

        org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> statementFactory.buildVerificationQueryPublicStatementFromRegistration(request)
        );
    }

    @Test
    void statementJtis_whenBuiltForTp2Statements_thenUseUuidV4() {
        assertThat(statementFactory.verificationQueryPublicJti()).satisfies(this::assertUuidV4);
        assertThat(statementFactory.protectedVerificationAuthorizationJti()).satisfies(this::assertUuidV4);
        assertThat(statementFactory.protectedIssuanceAuthorizationJti()).satisfies(this::assertUuidV4);
        assertThat(statementFactory.protectedIssuanceTrustListJti()).satisfies(this::assertUuidV4);
    }

    @Test
    void fixedRegistryDataset_whenQueriedByKnownSubjectOrJti_thenMatchesOnlyConfiguredEntries() {
        assertThat(statementFactory.buildVerificationQueryPublicStatements(
                Tp2TrustRegistryStatementFactory.TP2_DEFAULT_VERIFIER_SUBJECT
        )).hasSize(1);
        assertThat(statementFactory.buildVerificationQueryPublicStatements("did:tdw:QmUnknown:identifier.admin.ch:api:v1:did"))
                .isEmpty();
        assertThat(statementFactory.buildProtectedVerificationAuthorizationStatements(
                Tp2TrustRegistryStatementFactory.TP2_DEFAULT_VERIFIER_SUBJECT
        )).hasSize(1);
        assertThat(statementFactory.buildProtectedIssuanceAuthorizationStatements(issuerConfig.getIssuerDid()))
                .hasSize(1);
        assertThat(statementFactory.buildProtectedIssuanceAuthorizationStatements("did:tdw:QmUnknown:identifier.admin.ch:api:v1:did"))
                .isEmpty();
        assertThat(statementFactory.isKnownVerificationQueryPublicStatementJti(statementFactory.verificationQueryPublicJti()))
                .isTrue();
        assertThat(statementFactory.isKnownProtectedVerificationAuthorizationStatementJti(
                statementFactory.protectedVerificationAuthorizationJti()
        )).isTrue();
        assertThat(statementFactory.isKnownProtectedIssuanceAuthorizationStatementJti(
                statementFactory.protectedIssuanceAuthorizationJti()
        )).isTrue();
        assertThat(statementFactory.isKnownProtectedIssuanceTrustListStatementJti(
                statementFactory.protectedIssuanceTrustListJti()
        )).isTrue();
    }

    @Test
    void trustListEndpoints_whenBuilt_thenReturnSerializedTrustListStatements() throws ParseException {
        SignedJWT protectedIssuanceTrustList = SignedJWT.parse(statementFactory.buildProtectedIssuanceTrustList());
        SignedJWT nonComplianceTrustList = SignedJWT.parse(statementFactory.buildNonComplianceTrustList());

        assertThat(protectedIssuanceTrustList.getHeader().getType().toString())
                .isEqualTo("swiyu-protected-issuance-trust-list-statement+jwt");
        assertThat(protectedIssuanceTrustList.getJWTClaimsSet().getJWTID()).satisfies(this::assertUuidV4);
        assertThat(protectedIssuanceTrustList.getJWTClaimsSet().getSubject()).isNull();
        assertProtectedVctValues(protectedIssuanceTrustList.getJWTClaimsSet().getClaim("vct_values"));

        assertThat(nonComplianceTrustList.getHeader().getType().toString())
                .isEqualTo("swiyu-non-compliance-trust-list-statement+jwt");
        assertThat(nonComplianceTrustList.getJWTClaimsSet().getClaim("non_compliant_actors")).isInstanceOf(List.class);
        assertThat(nonComplianceTrustList.getJWTClaimsSet().getSubject()).isNull();
    }

    @Test
    void trustStatusListJwt_whenBuilt_thenIsIssuedByTrustRegistry() throws ParseException {
        SignedJWT statusList = SignedJWT.parse(statementFactory.buildTrustStatusListJwt());

        assertThat(statusList.getHeader().getType().toString()).isEqualTo("statuslist+jwt");
        assertThat(statusList.getHeader().getKeyID()).isEqualTo(trustConfig.getTrustAssertKeyId());
        assertThat(statusList.getHeader().getCustomParam("profile_version")).isNull();
        assertThat(statusList.getJWTClaimsSet().getIssuer()).isEqualTo(trustConfig.getTrustDid());
        assertThat(statusList.getJWTClaimsSet().getJSONObjectClaim("status_list")).containsKeys("bits", "lst");
    }

    @Test
    void pagedContent_whenPageAndSizeRequested_thenEchoesPagingShape() {
        HttpRequest request = HttpRequest.request()
                .withQueryStringParameter("page", "0")
                .withQueryStringParameter("size", "5");

        Map<String, Object> response = responseFactory.pagedContent(List.of("a", "b"), request);
        @SuppressWarnings("unchecked")
        List<String> content = (List<String>) response.get("content");
        @SuppressWarnings("unchecked")
        Map<String, Object> page = (Map<String, Object>) response.get("page");

        assertThat(response).containsKeys("content", "page");
        assertThat(content).containsExactly("a", "b");
        assertThat(page).containsEntry("number", 0)
                .containsEntry("size", 2)
                .containsEntry("totalPages", 1)
                .containsEntry("totalElements", 2);
    }

    private void assertUuidV4(String value) {
        assertThat(java.util.UUID.fromString(value).version()).isEqualTo(4);
    }

    private static Map<String, Object> tmsRegistrationRequest() {
        return new java.util.LinkedHashMap<>(Map.of(
                "sub", Tp2TrustRegistryStatementFactory.TP2_DEFAULT_VERIFIER_SUBJECT,
                "purpose_name#en", "Age verification",
                "purpose_description#en", "Verification of age for purchasing restricted goods",
                "scope", "com.example.age_verification_presentation",
                "query", new java.util.LinkedHashMap<>(Map.of(
                        "credentials", List.of(new java.util.LinkedHashMap<>(Map.of(
                                "id", "age-verification",
                                "format", "dc+sd-jwt",
                                "meta", new java.util.LinkedHashMap<>(Map.of(
                                        "vct_values", List.of(PROTECTED_VCT)
                                )),
                                "claims", List.of(Map.of("path", List.of("birth_date")))
                        )))
                ))
        ));
    }

    private static TrustConfig buildTrustConfig() {
        KeyPair trustKeyPair = generateEcKeyPair();
        return TrustConfig.builder()
                .trustDid(TRUST_DID)
                .trustDidLog("mock-trust-did-log")
                .trustAssertKeyId(TRUST_DID + "#assert-key-01")
                .trustAuthKeyId(TRUST_DID + "#auth-key-01")
                .trustAssertKeyPemString(toPem(trustKeyPair))
                .trustAuthKeyPemString(toPem(trustKeyPair))
                .build();
    }

    private static IssuerConfig buildIssuerConfig() {
        KeyPair issuerKeyPair = generateEcKeyPair();
        return IssuerConfig.builder()
                .issuerDid(ISSUER_DID)
                .issuerDidLog("mock-issuer-did-log")
                .issuerAssertKeyId(ISSUER_DID + "#assert-key-01")
                .issuerAuthKeyId(ISSUER_DID + "#auth-key-01")
                .issuerAssertKeyPemString(toPem(issuerKeyPair))
                .issuerAuthKeyPemString(toPem(issuerKeyPair))
                .keyPair(issuerKeyPair)
                .build();
    }

    private static KeyPair generateEcKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Cannot generate EC test key pair", e);
        }
    }

    private static String toPem(KeyPair keyPair) {
        String privateKeyBase64 = Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(keyPair.getPrivate().getEncoded());
        String publicKeyBase64 = Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(keyPair.getPublic().getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + privateKeyBase64 + "\n-----END PRIVATE KEY-----\n"
                + "-----BEGIN PUBLIC KEY-----\n" + publicKeyBase64 + "\n-----END PUBLIC KEY-----\n";
    }

    private void assertProtectedVctUrl(String vct) {
        assertThat(vct)
                .isEqualTo(PROTECTED_VCT)
                .startsWith(TestConstants.ISSUER_URL + "/oid4vci/vct/");
    }

    private void assertProtectedVctValues(Object vctValues) {
        assertThat(vctValues).isEqualTo(List.of(PROTECTED_VCT));
        assertProtectedVctUrl((String) ((List<?>) vctValues).getFirst());
    }
}
