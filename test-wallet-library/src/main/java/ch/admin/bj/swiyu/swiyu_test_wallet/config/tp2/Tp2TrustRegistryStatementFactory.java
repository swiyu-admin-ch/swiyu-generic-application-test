package ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2;

import ch.admin.bj.swiyu.jwtutil.JwtUtil;
import ch.admin.bj.swiyu.jwtutil.JwtUtilException;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.TrustConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.TestSupportException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

final class Tp2TrustRegistryStatementFactory {

    static final String TP2_PROFILE_VERSION = "swiss-profile-trust:2.0.0";
    static final String TP2_DEFAULT_VERIFIER_SUBJECT = "did:tdw:mock-verifier";
    static final String TP2_PROTECTED_VCT = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;
    static final String TP2_AUTHORIZED_FIELD = "personal_administrative_number";

    private static final String TP2_DEFAULT_VERIFICATION_QUERY_ID = "employment-verification";
    private static final String TP2_DEFAULT_VERIFICATION_SCOPE = "ch.swiyu.tp2.employment.presentation";
    private static final String TP2_STATUS_LIST_URI = "https://mockserver:1080/api/v1/statuslist/tp2-trust-statements.jwt";
    private static final String IDENTITY_TRUST_STATEMENT_TYPE = "swiyu-identity-trust-statement+jwt";
    private static final String VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE =
            "swiyu-verification-query-public-statement+jwt";
    private static final String PROTECTED_VERIFICATION_AUTHORIZATION_TYPE =
            "swiyu-protected-verification-authorization-trust-statement+jwt";
    private static final String PROTECTED_ISSUANCE_AUTHORIZATION_TYPE =
            "swiyu-protected-issuance-authorization-trust-statement+jwt";
    private static final String PROTECTED_ISSUANCE_TRUST_LIST_STATEMENT_TYPE =
            "swiyu-protected-issuance-trust-list-statement+jwt";
    private static final List<String> PROTECTED_FIELD_NAMES = List.of(TP2_AUTHORIZED_FIELD);
    private static final List<String> PROTECTED_VCT_VALUES = List.of(TP2_PROTECTED_VCT);

    private final IssuerConfig issuerConfig;
    private final TrustConfig trustConfig;

    Tp2TrustRegistryStatementFactory(IssuerConfig issuerConfig, TrustConfig trustConfig) {
        this.issuerConfig = issuerConfig;
        this.trustConfig = trustConfig;
    }

    List<String> buildIdentityTrustStatements(String requestedSubject) {
        if (requestedSubject != null) {
            return List.of(buildIdentityTrustStatement(requestedSubject));
        }

        return List.of(
                buildIdentityTrustStatement(issuerSubject()),
                buildIdentityTrustStatement(defaultVerifierSubject())
        );
    }

    String buildIdentityTrustStatement(String subject) {
        return createStatement(
                IDENTITY_TRUST_STATEMENT_TYPE,
                subject,
                deterministicUuid("tp2-identity-" + subject),
                Map.of(
                        "status", buildStatusClaim(),
                        "entity_name", resolveEntityName(subject),
                        "is_state_actor", Boolean.TRUE,
                        "registry_ids", List.of(Map.of("type", "UID", "value", "CHE-123.456.789"))
                )
        );
    }

    String buildVerificationQueryPublicStatement(String subject, String jti) {
        return createStatement(
                VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE,
                subject,
                jti,
                Map.of(
                        "purpose_name", "Employment check",
                        "purpose_name#de-CH", "Beschaeftigungspruefung",
                        "purpose_description", "Mock TP2 verification request used by application tests.",
                        "purpose_description#de-CH", "Mock-TP2-Verifizierungsanfrage fuer Anwendungstests.",
                        "request", buildVerificationRequest()
                )
        );
    }

    String buildProtectedVerificationAuthorizationStatement(String subject, String jti) {
        return createStatement(
                PROTECTED_VERIFICATION_AUTHORIZATION_TYPE,
                subject,
                jti,
                Map.of(
                        "status", buildStatusClaim(),
                        "authorized_fields", PROTECTED_FIELD_NAMES
                )
        );
    }

    String buildProtectedIssuanceAuthorizationStatement(String subject, String jti) {
        return createStatement(
                PROTECTED_ISSUANCE_AUTHORIZATION_TYPE,
                subject,
                jti,
                Map.of(
                        "status", buildStatusClaim(),
                        "can_issue", Map.of(
                                "vct", TP2_PROTECTED_VCT,
                                "vct_name", "Bound Example SD-JWT VC",
                                "vct_name#de-CH", "Gebundene Beispiel-SD-JWT-VC",
                                "reason", "This issuer is allowed to issue the protected example credential.",
                                "reason#de-CH", "Dieser Issuer darf das geschuetzte Beispiel-Credential ausstellen."
                        )
                )
        );
    }

    String buildProtectedIssuanceTrustListStatement(String jti) {
        return createStatement(
                PROTECTED_ISSUANCE_TRUST_LIST_STATEMENT_TYPE,
                trustConfig.getTrustDid(),
                jti,
                Map.of(
                        "status", buildStatusClaim(),
                        "vct_values", PROTECTED_VCT_VALUES
                )
        );
    }

    Map<String, Object> buildProtectedIssuanceTrustList() {
        return Map.of("vct_values", PROTECTED_VCT_VALUES);
    }

    Map<String, Object> buildNonComplianceTrustList() {
        return Map.of(
                "non_compliant_actors", List.of(Map.of(
                        "actor", "did:tdw:mock-bad-actor",
                        "flagged_at", "2026-02-25T07:07:35Z",
                        "reason", "Mock bad actor entry used by application tests.",
                        "reason#de-CH", "Mock-Eintrag fuer boeswilligen Akteur in Anwendungstests."
                ))
        );
    }

    String defaultVerifierSubject() {
        return TP2_DEFAULT_VERIFIER_SUBJECT;
    }

    String issuerSubject() {
        return issuerConfig.getIssuerDid();
    }

    String resolveVerifierSubject(String requestedSubject) {
        return requestedSubject == null || requestedSubject.isBlank() ? defaultVerifierSubject() : requestedSubject;
    }

    String resolveIssuerSubject(String requestedSubject) {
        return requestedSubject == null || requestedSubject.isBlank() ? issuerSubject() : requestedSubject;
    }

    String verificationQueryPublicJti() {
        return deterministicUuid("tp2-verification-query-public");
    }

    String protectedVerificationAuthorizationJti() {
        return deterministicUuid("tp2-protected-verification-authorization");
    }

    String protectedIssuanceAuthorizationJti() {
        return deterministicUuid("tp2-protected-issuance-authorization");
    }

    String protectedIssuanceTrustListJti() {
        return deterministicUuid("tp2-protected-issuance-trust-list");
    }

    private Map<String, Object> buildStatusClaim() {
        return Map.of(
                "status_list", Map.of(
                        "idx", 0,
                        "uri", TP2_STATUS_LIST_URI
                )
        );
    }

    private Map<String, Object> buildVerificationRequest() {
        return Map.of(
                "type", "DCQL",
                "scope", TP2_DEFAULT_VERIFICATION_SCOPE,
                "query", Map.of(
                        "credentials", List.of(Map.of(
                                "id", TP2_DEFAULT_VERIFICATION_QUERY_ID,
                                "format", "dc+sd-jwt",
                                "meta", Map.of("vct_values", PROTECTED_VCT_VALUES),
                                "claims", List.of(
                                        Map.of("path", List.of("last_name")),
                                        Map.of("path", List.of("first_name"))
                                )
                        ))
                )
        );
    }

    private String createStatement(String type, String subject, String jti, Map<String, Object> claims) {
        try {
            final JWK trustJwk = JWK.parseFromPEMEncodedObjects(trustConfig.getTrustAssertKeyPemString());
            final JWSSigner signer = new ECDSASigner(trustJwk.toECKey());

            final Date now = new Date();
            final JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                    .issuer(trustConfig.getTrustDid())
                    .subject(subject)
                    .jwtID(jti)
                    .issueTime(now)
                    .expirationTime(new Date(now.getTime() + 3_600_000));

            claims.forEach(builder::claim);

            final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(trustConfig.getTrustAssertKeyId())
                    .type(new JOSEObjectType(type))
                    .customParam("profile_version", TP2_PROFILE_VERSION)
                    .build();

            return JwtUtil.signJwt(builder.build(), header, signer).serialize();
        } catch (JOSEException | JwtUtilException e) {
            throw new TestSupportException("Cannot build TP2 trust-registry statement: " + e.getMessage());
        }
    }

    private String resolveEntityName(String subject) {
        if (subject.equals(issuerSubject())) {
            return "Mock TP2 Issuer";
        }
        if (subject.equals(defaultVerifierSubject())) {
            return "Mock TP2 Verifier";
        }
        if (subject.equals(trustConfig.getTrustDid())) {
            return "Mock TP2 Trust Registry";
        }
        return "Mock TP2 Actor";
    }

    private String deterministicUuid(String seed) {
        return UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8)).toString();
    }
}
