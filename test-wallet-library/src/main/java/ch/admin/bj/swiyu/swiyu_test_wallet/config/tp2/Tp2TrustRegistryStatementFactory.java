package ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.TrustConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.support.TestConstants;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.TestSupportException;
import ch.admin.bj.swiyu.tsbuilder.IdTsBuilder;
import ch.admin.bj.swiyu.tsbuilder.NcTlsBuilder;
import ch.admin.bj.swiyu.tsbuilder.PiTlsBuilder;
import ch.admin.bj.swiyu.tsbuilder.PiaTsBuilder;
import ch.admin.bj.swiyu.tsbuilder.PvaTsBuilder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

final class Tp2TrustRegistryStatementFactory {

    static final String TP2_PROFILE_VERSION = "swiss-profile-trust:1.0.0";
    static final String TP2_DEFAULT_VERIFIER_SUBJECT =
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRBB1:identifier.admin.ch:api:v1:did";
    static final String TP2_PROTECTED_VCT = TestConstants.ISSUER_URL + "/oid4vci/vct/my-vct-v01";
    static final String TP2_AUTHORIZED_FIELD = "personal_administrative_number";

    private static final String TP2_BAD_ACTOR_SUBJECT =
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRCC1:identifier.admin.ch:api:v1:did";
    private static final String TP2_DEFAULT_VERIFICATION_QUERY_ID = "employment-verification";
    private static final String TP2_DEFAULT_VERIFICATION_SCOPE = "ch.swiyu.tp2.employment.presentation";
    private static final String TP2_STATUS_LIST_URI = "https://mockserver:1080/api/v1/statuslist/tp2-trust-statements.jwt";
    private static final String STATUS_LIST_TYPE = "statuslist+jwt";
    private static final String VQPS_TYPE = "swiyu-verification-query-public-statement+jwt";
    private static final int VQPS_MAX_PURPOSE_NAME_LENGTH = 40;
    private static final int VQPS_MAX_PURPOSE_DESCRIPTION_LENGTH = 1000;
    private static final String TP2_STATUS_LIST_BITS =
            "eNrtwQEBAAAAgiD_r25IQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHwYYagAAQ";
    private static final List<String> PROTECTED_FIELD_NAMES = List.of(TP2_AUTHORIZED_FIELD);
    private static final List<String> PROTECTED_VCT_VALUES = List.of(TP2_PROTECTED_VCT);
    private static final Duration ISSUED_AT_CLOCK_SKEW_CUSHION = Duration.ofMinutes(30);

    private final IssuerConfig issuerConfig;
    private final TrustConfig trustConfig;
    private final VerifierConfig verifierConfig;
    private final Map<String, PublishedVerificationQueryPublicStatement> publishedVerificationQueryPublicStatements =
            new HashMap<>();

    record PublishedVerificationQueryPublicStatement(String subject, String jti, String jwt) { }

    Tp2TrustRegistryStatementFactory(IssuerConfig issuerConfig, TrustConfig trustConfig) {
        this(issuerConfig, null, trustConfig);
    }

    Tp2TrustRegistryStatementFactory(IssuerConfig issuerConfig, VerifierConfig verifierConfig, TrustConfig trustConfig) {
        this.issuerConfig = issuerConfig;
        this.verifierConfig = verifierConfig;
        this.trustConfig = trustConfig;
    }

    List<String> buildIdentityTrustStatements(String requestedSubject) {
        if (requestedSubject != null) {
            return knownIdentitySubjects().stream()
                    .filter(subject -> Objects.equals(subject, requestedSubject))
                    .map(this::buildIdentityTrustStatement)
                    .toList();
        }

        return knownIdentitySubjects().stream()
                .map(this::buildIdentityTrustStatement)
                .toList();
    }

    String buildIdentityTrustStatement(String subject) {
        return buildIdentityTrustStatement(subject, Duration.ofHours(1));
    }

    String buildIdentityTrustStatement(String subject, Duration lifetime) {
        String entityName = resolveEntityName(subject);
        SignedJWT statement = new AccessibleIdTsBuilder()
                .withTrustRegistryMetadata(
                        trustConfig.getTrustAssertKeyId(),
                        subject,
                        issuedAt(),
                        expiresAt(lifetime)
                )
                .withStatus(0, TP2_STATUS_LIST_URI)
                .withJti(UUID.randomUUID().toString())
                .addEntityName(entityName)
                .addEntityName(entityName, "en")
                .addEntityName(entityName + " Schweiz", "de-CH")
                .withIsStateActor(true)
                .addRegistryId("UID", "CHE-123.456.789")
                .addRegistryId("LEI", "0A1B2C3D4E5F6G7H8J9I")
                .build();

        return sign(statement);
    }

    String buildVerificationQueryPublicStatement(String subject, String jti) {
        return buildVerificationQueryPublicStatement(subject, jti, Duration.ofHours(1));
    }

    String buildVerificationQueryPublicStatement(String subject, String jti, Duration lifetime) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("purpose_name", "Employment check");
        claims.put("purpose_name#en", "Employment check");
        claims.put("purpose_name#de-CH", "Beschaeftigungspruefung");
        claims.put("purpose_description", "Mock TP2 verification request used by application tests.");
        claims.put("purpose_description#en", "Mock TP2 verification request used by application tests.");
        claims.put("purpose_description#de-CH", "Mock-TP2-Verifizierungsanfrage fuer Anwendungstests.");
        claims.put("request", verificationRequest(TP2_DEFAULT_VERIFICATION_SCOPE, buildVerificationQuery()));

        return createVerificationQueryPublicStatement(subject, jti, lifetime, claims);
    }

    List<String> buildVerificationQueryPublicStatements(String requestedSubject) {
        List<String> statements = new ArrayList<>();

        if (requestedSubject == null || requestedSubject.equals(defaultVerifierSubject())) {
            statements.add(buildVerificationQueryPublicStatement(defaultVerifierSubject(), verificationQueryPublicJti()));
        }

        publishedVerificationQueryPublicStatements.values().stream()
                .filter(statement -> requestedSubject == null || requestedSubject.equals(statement.subject()))
                .sorted(Comparator.comparing(PublishedVerificationQueryPublicStatement::jti))
                .map(PublishedVerificationQueryPublicStatement::jwt)
                .forEach(statements::add);

        return statements;
    }

    String buildVerificationQueryPublicStatementFromRegistration(Map<String, Object> registrationRequest) {
        return publishVerificationQueryPublicStatementFromRegistration(registrationRequest).jwt();
    }

    PublishedVerificationQueryPublicStatement publishVerificationQueryPublicStatementFromRegistration(
            Map<String, Object> registrationRequest) {
        final String subject = requiredString(registrationRequest, "sub");
        final Map<String, Object> request = verificationRequest(registrationRequest);
        validateVerificationRequest(request);

        if (localizedClaimsMissing(registrationRequest, "purpose_name")) {
            throw new IllegalArgumentException("purpose_name is required");
        }
        if (localizedClaimsMissing(registrationRequest, "purpose_description")) {
            throw new IllegalArgumentException("purpose_description is required");
        }

        final String jti = UUID.randomUUID().toString();
        final Map<String, Object> claims = new LinkedHashMap<>();
        addLocalizedClaims(
                claims,
                registrationRequest,
                "purpose_name",
                VQPS_MAX_PURPOSE_NAME_LENGTH
        );
        addLocalizedClaims(
                claims,
                registrationRequest,
                "purpose_description",
                VQPS_MAX_PURPOSE_DESCRIPTION_LENGTH
        );
        claims.put("request", verificationRequest(requiredString(request, "scope"), requiredMap(request, "query")));

        PublishedVerificationQueryPublicStatement statement = new PublishedVerificationQueryPublicStatement(
                subject,
                jti,
                createVerificationQueryPublicStatement(subject, jti, Duration.ofHours(1), claims)
        );
        publishedVerificationQueryPublicStatements.put(statement.jti(), statement);
        return statement;
    }

    String buildProtectedVerificationAuthorizationStatement(String subject, String jti) {
        return buildProtectedVerificationAuthorizationStatement(subject, jti, Duration.ofHours(1));
    }

    String buildProtectedVerificationAuthorizationStatement(String subject, String jti, Duration lifetime) {
        SignedJWT statement = new AccessiblePvaTsBuilder()
                .withTrustRegistryMetadata(
                        trustConfig.getTrustAssertKeyId(),
                        subject,
                        issuedAt(),
                        expiresAt(lifetime)
                )
                .withStatus(0, TP2_STATUS_LIST_URI)
                .withJti(jti)
                .withAuthorizedFields(PROTECTED_FIELD_NAMES)
                .build();

        return sign(statement);
    }

    List<String> buildProtectedVerificationAuthorizationStatements(String requestedSubject) {
        if (requestedSubject != null && !requestedSubject.equals(defaultVerifierSubject())) {
            return List.of();
        }

        return List.of(buildProtectedVerificationAuthorizationStatement(
                defaultVerifierSubject(),
                protectedVerificationAuthorizationJti()
        ));
    }

    String buildProtectedIssuanceAuthorizationStatement(String subject, String jti) {
        return buildProtectedIssuanceAuthorizationStatement(subject, jti, Duration.ofHours(1), TP2_PROTECTED_VCT);
    }

    String buildProtectedIssuanceAuthorizationStatement(String subject, String jti, Duration lifetime, String vct) {
        SignedJWT statement = new AccessiblePiaTsBuilder()
                .withTrustRegistryMetadata(
                        trustConfig.getTrustAssertKeyId(),
                        subject,
                        issuedAt(),
                        expiresAt(lifetime)
                )
                .withStatus(0, TP2_STATUS_LIST_URI)
                .withJti(jti)
                .withCanIssue(
                        vct,
                        null,
                        "Bound Example SD-JWT VC",
                        "Protected example issuance."
                )
                .build();

        return sign(statement);
    }

    List<String> buildProtectedIssuanceAuthorizationStatements(String requestedSubject) {
        if (requestedSubject != null && !requestedSubject.equals(issuerSubject())) {
            return List.of();
        }

        return List.of(buildProtectedIssuanceAuthorizationStatement(
                issuerSubject(),
                protectedIssuanceAuthorizationJti()
        ));
    }

    String buildProtectedIssuanceTrustListStatement(String jti) {
        SignedJWT statement = new AccessiblePiTlsBuilder()
                .withTrustRegistryMetadata(
                        trustConfig.getTrustAssertKeyId(),
                        issuedAt(),
                        expiresAt()
                )
                .withStatus(0, TP2_STATUS_LIST_URI)
                .withJti(jti)
                .withVctValues(PROTECTED_VCT_VALUES)
                .build();

        return sign(statement);
    }

    List<String> buildProtectedIssuanceTrustListStatements() {
        return List.of(buildProtectedIssuanceTrustListStatement(protectedIssuanceTrustListJti()));
    }

    String buildProtectedIssuanceTrustList() {
        return buildProtectedIssuanceTrustListStatement(protectedIssuanceTrustListJti());
    }

    String buildNonComplianceTrustList() {
        SignedJWT statement = new AccessibleNcTlsBuilder()
                .withTrustRegistryMetadata(
                        trustConfig.getTrustAssertKeyId(),
                        issuedAt(),
                        expiresAt()
                )
                .withStatus(0, TP2_STATUS_LIST_URI)
                .addNonCompliantActor(
                        new NcTlsBuilder.NonCompliantActorBuilder(
                                TP2_BAD_ACTOR_SUBJECT,
                                "2026-02-25T07:07:35Z",
                                "Mock bad actor entry used by application tests.")
                                .addReason("de", "Mock bad actor entry used by application tests. (DE)")
                                .addReason("en", "Mock bad actor entry used by application tests. (EN)")
                                .addReason("fr-CH", "Mock bad actor entry used by application tests. (FR)")
                                .addReason("it-CH", "Mock bad actor entry used by application tests. (IT)")
                                .addReason("rm-CH", "Mock bad actor entry used by application tests. (RM)")
                                .build()
                )
                .addNonCompliantActor(
                        new NcTlsBuilder.NonCompliantActorBuilder(
                                defaultVerifierSubject(),
                                "2025-01-13T07:13:00Z",
                                "Mock verifier non-compliance entry used by application tests.")
                                .addReason("de", "Mock verifier non-compliance entry used by application tests. (DE)")
                                .addReason("en", "Mock verifier non-compliance entry used by application tests. (EN)")
                                .addReason("fr-CH", "Mock verifier non-compliance entry used by application tests. (FR)")
                                .addReason("it-CH", "Mock verifier non-compliance entry used by application tests. (IT)")
                                .addReason("rm-CH", "Mock verifier non-compliance entry used by application tests. (RM)")
                                .build()
                )
                .build();

        return sign(statement);
    }

    String buildTrustStatusListJwt() {
        return createSignedJwt(
                STATUS_LIST_TYPE,
                new JWTClaimsSet.Builder()
                        .issuer(trustConfig.getTrustDid())
                        .subject(TP2_STATUS_LIST_URI)
                        .issueTime(Date.from(issuedAt()))
                        .expirationTime(Date.from(expiresAt()))
                        .claim("status_list", Map.of(
                                "bits", "2",
                                "lst", TP2_STATUS_LIST_BITS
                        ))
                        .build(),
                false
        );
    }

    String defaultVerifierSubject() {
        return verifierConfig == null ? TP2_DEFAULT_VERIFIER_SUBJECT : verifierConfig.getVerifierDid();
    }

    String issuerSubject() {
        return issuerConfig.getIssuerDid();
    }

    String verificationQueryPublicJti() {
        return "07f289d5-8b1f-4604-bf72-53bdcb71ee05";
    }

    String protectedVerificationAuthorizationJti() {
        return "a8b1110d-f7c5-46da-9db1-8f4c89e8ff0d";
    }

    String protectedIssuanceAuthorizationJti() {
        return "d6ce2b08-e91d-4504-8fe3-0f214465db25";
    }

    String protectedIssuanceTrustListJti() {
        return "fd841f09-e413-4ef3-9db2-9c1d7538c3a1";
    }

    boolean isKnownIdentitySubject(String subject) {
        return knownIdentitySubjects().contains(subject);
    }

    boolean isKnownVerificationQueryPublicStatementJti(String jti) {
        return verificationQueryPublicJti().equals(jti) || publishedVerificationQueryPublicStatements.containsKey(jti);
    }

    Optional<String> findVerificationQueryPublicStatement(String jti) {
        if (verificationQueryPublicJti().equals(jti)) {
            return Optional.of(buildVerificationQueryPublicStatement(defaultVerifierSubject(), jti));
        }
        return Optional.ofNullable(publishedVerificationQueryPublicStatements.get(jti))
                .map(PublishedVerificationQueryPublicStatement::jwt);
    }

    boolean isKnownProtectedVerificationAuthorizationStatementJti(String jti) {
        return protectedVerificationAuthorizationJti().equals(jti);
    }

    boolean isKnownProtectedIssuanceAuthorizationStatementJti(String jti) {
        return protectedIssuanceAuthorizationJti().equals(jti);
    }

    boolean isKnownProtectedIssuanceTrustListStatementJti(String jti) {
        return protectedIssuanceTrustListJti().equals(jti);
    }

    private Instant issuedAt() {
        return Instant.now().minus(ISSUED_AT_CLOCK_SKEW_CUSHION).truncatedTo(ChronoUnit.SECONDS);
    }

    private Instant expiresAt() {
        return expiresAt(Duration.ofHours(1));
    }

    private Instant expiresAt(Duration lifetime) {
        return Instant.now().plus(lifetime).truncatedTo(ChronoUnit.SECONDS);
    }

    private Map<String, Object> buildVerificationQuery() {
        return Map.of(
                "credentials", List.of(Map.of(
                        "id", TP2_DEFAULT_VERIFICATION_QUERY_ID,
                        "format", "dc+sd-jwt",
                        "meta", Map.of("vct_values", PROTECTED_VCT_VALUES),
                        "claims", List.of(
                                Map.of("path", List.of("last_name")),
                                Map.of("path", List.of("first_name"))
                        )
                ))
        );
    }

    private String createVerificationQueryPublicStatement(String subject,
                                                          String jti,
                                                          Duration lifetime,
                                                          Map<String, Object> claims) {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .subject(subject)
                .issueTime(Date.from(issuedAt()))
                .expirationTime(Date.from(expiresAt(lifetime)));
        if (jti != null) {
            claimsBuilder.jwtID(jti);
        }
        claims.forEach(claimsBuilder::claim);
        return createSignedJwt(VQPS_TYPE, claimsBuilder.build(), true);
    }

    private Map<String, Object> verificationRequest(String scope, Map<String, Object> query) {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("type", "DCQL");
        request.put("scope", scope);
        request.put("query", query);
        return request;
    }

    private String requiredString(Map<String, Object> source, String claimName) {
        final Object value = source.get(claimName);
        if (!(value instanceof String stringValue) || stringValue.isBlank()) {
            throw new IllegalArgumentException(claimName + " is required");
        }
        return stringValue;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> requiredMap(Map<String, Object> source, String claimName) {
        final Object value = source.get(claimName);
        if (!(value instanceof Map<?, ?> mapValue)) {
            throw new IllegalArgumentException(claimName + " is required");
        }
        return (Map<String, Object>) mapValue;
    }

    @SuppressWarnings("unchecked")
    private void validateVerificationRequest(Map<String, Object> request) {
        if (!"DCQL".equals(request.get("type"))) {
            throw new IllegalArgumentException("request.type must be DCQL");
        }
        if (!(request.get("scope") instanceof String scope) || scope.isBlank()) {
            throw new IllegalArgumentException("request.scope is required");
        }
        final Object query = request.get("query");
        if (!(query instanceof Map<?, ?> queryMap)) {
            throw new IllegalArgumentException("request.query is required");
        }
        final Object credentials = queryMap.get("credentials");
        if (!(credentials instanceof List<?> credentialList) || credentialList.isEmpty()) {
            throw new IllegalArgumentException("query.credentials must be a non-empty array");
        }
        for (Object credential : credentialList) {
            if (!(credential instanceof Map<?, ?> credentialMap)) {
                throw new IllegalArgumentException("query.credentials entries must be objects");
            }
            final Object meta = credentialMap.get("meta");
            if (!(meta instanceof Map<?, ?> metaMap)) {
                throw new IllegalArgumentException("query.credentials.meta is required");
            }
            final Object vctValues = metaMap.get("vct_values");
            if (!(vctValues instanceof List<?> vctValuesList) || vctValuesList.isEmpty()) {
                throw new IllegalArgumentException("query.credentials.meta.vct_values must be a non-empty array");
            }
        }
    }

    private Map<String, Object> verificationRequest(Map<String, Object> registrationRequest) {
        if (registrationRequest.containsKey("request")) {
            return requiredMap(registrationRequest, "request");
        }

        return Map.of(
                "type", "DCQL",
                "scope", requiredString(registrationRequest, "scope"),
                "query", requiredMap(registrationRequest, "query")
        );
    }

    private boolean localizedClaimsMissing(Map<String, Object> source, String baseClaim) {
        return source.keySet().stream()
                .noneMatch(key -> key.equals(baseClaim) || key.startsWith(baseClaim + "#"));
    }

    private void addLocalizedClaims(Map<String, Object> claims,
                                    Map<String, Object> source,
                                    String baseClaim,
                                    int maxLength) {
        Optional<String> firstValue = source.entrySet().stream()
                .filter(entry -> entry.getKey().equals(baseClaim) || entry.getKey().startsWith(baseClaim + "#"))
                .flatMap(entry -> localizedClaimValues(entry.getKey(), entry.getValue()).stream())
                .peek(value -> validateMaxLength(value.value(), maxLength, value.key()))
                .findFirst()
                .map(LocalizedClaim::value);

        source.forEach((key, value) -> {
            if (key.equals(baseClaim)) {
                if (value instanceof Map<?, ?> localizedValues) {
                    addLocalizedClaims(claims, baseClaim, localizedValues, maxLength);
                } else {
                    String stringValue = asString(value, key);
                    validateMaxLength(stringValue, maxLength, key);
                    claims.put(baseClaim, stringValue);
                }
            } else if (key.startsWith(baseClaim + "#")) {
                String stringValue = asString(value, key);
                validateMaxLength(stringValue, maxLength, key);
                claims.put(key, stringValue);
            }
        });

        if (!claims.containsKey(baseClaim)) {
            claims.put(baseClaim, firstValue.orElseThrow(() -> new IllegalArgumentException(baseClaim + " is required")));
        }
    }

    private void addLocalizedClaims(Map<String, Object> claims,
                                    String baseClaim,
                                    Map<?, ?> localizedValues,
                                    int maxLength) {
        localizedValues.forEach((locale, value) -> {
            String key = baseClaim + "#" + locale;
            String stringValue = asString(value, key);
            validateMaxLength(stringValue, maxLength, key);
            claims.put(key, stringValue);
        });
    }

    private List<LocalizedClaim> localizedClaimValues(String key, Object value) {
        if (value instanceof Map<?, ?> localizedValues) {
            return localizedValues.entrySet().stream()
                    .map(entry -> {
                        String localizedKey = key + "#" + entry.getKey();
                        return new LocalizedClaim(localizedKey, asString(entry.getValue(), localizedKey));
                    })
                    .toList();
        }
        return List.of(new LocalizedClaim(key, asString(value, key)));
    }

    private void validateMaxLength(String value, int maxLength, String claimName) {
        if (value.length() > maxLength) {
            throw new IllegalArgumentException(claimName + " must not contain more than " + maxLength + " characters");
        }
    }

    private String asString(Object value, String claimName) {
        if (!(value instanceof String stringValue) || stringValue.isBlank()) {
            throw new IllegalArgumentException(claimName + " must be a non-empty string");
        }
        return stringValue;
    }

    private record LocalizedClaim(String key, String value) { }

    private String sign(SignedJWT statement) {
        try {
            statement.sign(trustSigner());
            return statement.serialize();
        } catch (JOSEException e) {
            throw new TestSupportException("Cannot sign TP2 trust-registry statement: " + e.getMessage());
        }
    }

    private String createSignedJwt(String type, JWTClaimsSet claimsSet, boolean includeProfileVersion) {
        try {
            final JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(trustConfig.getTrustAssertKeyId())
                    .type(new JOSEObjectType(type));
            if (includeProfileVersion) {
                headerBuilder.customParam("profile_version", TP2_PROFILE_VERSION);
            }

            SignedJWT statement = new SignedJWT(headerBuilder.build(), claimsSet);
            statement.sign(trustSigner());
            return statement.serialize();
        } catch (JOSEException e) {
            throw new TestSupportException("Cannot build TP2 trust-registry statement: " + e.getMessage());
        }
    }

    private JWSSigner trustSigner() throws JOSEException {
        final JWK trustJwk = JWK.parseFromPEMEncodedObjects(trustConfig.getTrustAssertKeyPemString());
        return new ECDSASigner(trustJwk.toECKey());
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

    private List<String> knownIdentitySubjects() {
        return List.of(issuerSubject(), defaultVerifierSubject());
    }

    private static final class AccessibleIdTsBuilder extends IdTsBuilder {
        IdTsBuilder withTrustRegistryMetadata(String kid, String subject, Instant issuedAt, Instant expiresAt) {
            withKid(kid);
            withSubject(subject);
            withValidity(issuedAt, expiresAt);
            return this;
        }
    }

    private static final class AccessiblePvaTsBuilder extends PvaTsBuilder {
        PvaTsBuilder withTrustRegistryMetadata(String kid, String subject, Instant issuedAt, Instant expiresAt) {
            withKid(kid);
            withSubject(subject);
            withValidity(issuedAt, expiresAt);
            return this;
        }
    }

    private static final class AccessiblePiaTsBuilder extends PiaTsBuilder {
        PiaTsBuilder withTrustRegistryMetadata(String kid, String subject, Instant issuedAt, Instant expiresAt) {
            withKid(kid);
            withSubject(subject);
            withValidity(issuedAt, expiresAt);
            return this;
        }
    }

    private static final class AccessiblePiTlsBuilder extends PiTlsBuilder {
        PiTlsBuilder withTrustRegistryMetadata(String kid, Instant issuedAt, Instant expiresAt) {
            withKid(kid);
            withValidity(issuedAt, expiresAt);
            return this;
        }
    }

    private static final class AccessibleNcTlsBuilder extends NcTlsBuilder {
        NcTlsBuilder withTrustRegistryMetadata(String kid, Instant issuedAt, Instant expiresAt) {
            withKid(kid);
            withValidity(issuedAt, expiresAt);
            return this;
        }
    }
}
