package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.gen.verifier.model.DcqlQueryDto;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerifierInfoEntryDto;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.TrustConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.TestSupportException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;

final class VerificationQueryResolver {

    static final String VQPS_TYPE = "swiyu-verification-query-public-statement+jwt";
    static final String TP2_PROFILE_VERSION = "swiss-profile-trust:1.0.0";

    private static final String JWT_FORMAT = "jwt";
    private static final String DCQL_TYPE = "DCQL";
    private static final String DECENTRALIZED_IDENTIFIER_PREFIX = "decentralized_identifier:";

    private final Clock clock;
    private final ObjectMapper objectMapper = JsonMapper.builder()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    VerificationQueryResolver() {
        this(Clock.systemUTC());
    }

    VerificationQueryResolver(final Clock clock) {
        this.clock = clock;
    }

    DcqlQueryDto resolve(final RequestObject requestObject, final TrustConfig trustConfig) {
        Objects.requireNonNull(requestObject, "requestObject must not be null");

        if (requestObject.getDcqlQuery() != null) {
            return requestObject.getDcqlQuery();
        }

        if (trustConfig == null) {
            throw invalidRequest("TP2 trust configuration is required to validate a vqPS");
        }

        final SignedJWT vqPs = selectVqPs(requestObject.getVerifierInfo());
        validateHeader(vqPs, trustConfig);
        verifySignature(vqPs, trustConfig);

        final JWTClaimsSet claims = claims(vqPs);
        validateLifetime(claims);
        validateSubject(claims, requestObject.getClientId());

        final Map<String, Object> verificationRequest = jsonObjectClaim(claims, "request");
        if (!DCQL_TYPE.equals(requiredString(verificationRequest, "type"))) {
            throw invalidRequest("vqPS request.type must be DCQL");
        }

        final String requestScope = requireNonBlank(requestObject.getScope(), "Authorization Request scope is required");
        final String vqPsScope = requiredString(verificationRequest, "scope");
        if (!requestScope.equals(vqPsScope)) {
            throw invalidRequest("Authorization Request scope must match the vqPS request.scope");
        }

        final Object query = verificationRequest.get("query");
        if (!(query instanceof Map<?, ?>)) {
            throw invalidRequest("vqPS request.query must be a JSON object");
        }

        final DcqlQueryDto dcqlQuery;
        try {
            dcqlQuery = objectMapper.convertValue(query, DcqlQueryDto.class);
        } catch (final IllegalArgumentException exception) {
            throw invalidRequest("vqPS request.query is not valid DCQL");
        }

        if (dcqlQuery.getCredentials() == null || dcqlQuery.getCredentials().isEmpty()) {
            throw invalidRequest("vqPS DCQL query must contain at least one credential query");
        }
        dcqlQuery.getCredentials().forEach(credential ->
                requireNonBlank(credential.getId(), "vqPS credential query id is required"));
        return dcqlQuery;
    }

    private SignedJWT selectVqPs(final List<VerifierInfoEntryDto> verifierInfo) {
        if (verifierInfo == null || verifierInfo.isEmpty()) {
            throw invalidRequest("verifier_info must contain exactly one vqPS");
        }

        final List<Map.Entry<VerifierInfoEntryDto, SignedJWT>> statements = verifierInfo.stream()
                .map(entry -> Map.entry(entry, parseStatement(entry.getData())))
                .filter(entry -> entry.getValue().getHeader().getType() != null)
                .filter(entry -> VQPS_TYPE.equals(entry.getValue().getHeader().getType().getType()))
                .toList();

        if (statements.size() != 1) {
            throw invalidRequest("verifier_info must contain exactly one vqPS");
        }
        final Map.Entry<VerifierInfoEntryDto, SignedJWT> vqPs = statements.getFirst();
        if (!JWT_FORMAT.equals(vqPs.getKey().getFormat())) {
            throw invalidRequest("vqPS verifier_info format must be jwt");
        }
        return vqPs.getValue();
    }

    private SignedJWT parseStatement(final String serializedStatement) {
        final String statement = requireNonBlank(serializedStatement, "verifier_info JWT data is required");
        try {
            return SignedJWT.parse(statement);
        } catch (final ParseException exception) {
            throw invalidRequest("verifier_info contains an invalid compact JWT");
        }
    }

    private void validateHeader(final SignedJWT vqPs, final TrustConfig trustConfig) {
        if (!JWSAlgorithm.ES256.equals(vqPs.getHeader().getAlgorithm())) {
            throw invalidRequest("vqPS must use ES256");
        }
        if (vqPs.getHeader().getType() == null
                || !VQPS_TYPE.equals(vqPs.getHeader().getType().getType())) {
            throw invalidRequest("vqPS typ is invalid");
        }
        if (!TP2_PROFILE_VERSION.equals(vqPs.getHeader().getCustomParam("profile_version"))) {
            throw invalidRequest("vqPS profile_version is invalid");
        }
        if (!Objects.equals(trustConfig.getTrustAssertKeyId(), vqPs.getHeader().getKeyID())) {
            throw invalidRequest("vqPS kid is not the configured TP2 trust assertion key");
        }
    }

    private void verifySignature(final SignedJWT vqPs, final TrustConfig trustConfig) {
        try {
            final JWK trustKey = JWK.parse(trustConfig.getTrustAssertPublicJwk());
            if (!vqPs.verify(new ECDSAVerifier(trustKey.toECKey()))) {
                throw invalidRequest("vqPS signature is invalid");
            }
        } catch (final JOSEException | ParseException exception) {
            throw invalidRequest("vqPS signature cannot be validated");
        }
    }

    private JWTClaimsSet claims(final SignedJWT vqPs) {
        try {
            return vqPs.getJWTClaimsSet();
        } catch (final ParseException exception) {
            throw invalidRequest("vqPS claims cannot be parsed");
        }
    }

    private void validateLifetime(final JWTClaimsSet claims) {
        final Instant now = clock.instant();
        final Date issuedAt = claims.getIssueTime();
        final Date expiresAt = claims.getExpirationTime();

        if (issuedAt == null || issuedAt.toInstant().isAfter(now)) {
            throw invalidRequest("vqPS iat is missing or in the future");
        }
        if (expiresAt == null || !expiresAt.toInstant().isAfter(now)) {
            throw invalidRequest("vqPS is expired or has no exp");
        }
    }

    private void validateSubject(final JWTClaimsSet claims, final String clientId) {
        final String normalizedClientId = requireNonBlank(clientId, "Authorization Request client_id is required")
                .replaceFirst("^" + DECENTRALIZED_IDENTIFIER_PREFIX, "");
        if (!normalizedClientId.equals(claims.getSubject())) {
            throw invalidRequest("vqPS subject must match the Authorization Request client_id");
        }
    }

    private Map<String, Object> jsonObjectClaim(final JWTClaimsSet claims, final String claimName) {
        try {
            final Map<String, Object> value = claims.getJSONObjectClaim(claimName);
            if (value == null) {
                throw invalidRequest("vqPS " + claimName + " claim is required");
            }
            return value;
        } catch (final ParseException exception) {
            throw invalidRequest("vqPS " + claimName + " claim must be a JSON object");
        }
    }

    private String requiredString(final Map<String, Object> values, final String key) {
        final Object value = values.get(key);
        if (!(value instanceof String stringValue)) {
            throw invalidRequest("vqPS request." + key + " must be a string");
        }
        return requireNonBlank(stringValue, "vqPS request." + key + " is required");
    }

    private String requireNonBlank(final String value, final String message) {
        if (value == null || value.isBlank()) {
            throw invalidRequest(message);
        }
        return value;
    }

    private TestSupportException invalidRequest(final String message) {
        return new TestSupportException(message);
    }
}
