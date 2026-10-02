package ch.admin.bj.swiyu.swiyu_test_wallet.mock;

import ch.admin.bj.swiyu.swiyu_test_wallet.identity.KeyUtil;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.HttpStatusCode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;

/**
 * The Status Registry of the Base Registry: creates status list entries, receives the lists the Credential Issuer publishes
 * (PUT), and serves them as Status List Tokens ({@code application/statuslist+jwt}, Token Status List draft 20 §5, Swiss VC
 * profile). The mock signs the served token itself with the key of the issuer the list belongs to.
 *
 * <p>It serves both update endpoints of the Status Registry: v1 (deprecated, no conformity check) and v2 (Swiss profile
 * conformity enforced, see {@link SwissStatusListConformity}). Creating an entry and reading a list exist in v1 only. A
 * Credential Issuer uses the v2 update from the image {@code main} on and the v1 one before.
 *
 * <p>It can be told to fail updates or to serve a token with a corrupted signature, for the tests that need a faulty
 * registry.
 */
@Slf4j
final class StatusRegistry {

    private static final String UPDATE_PATH_V1 =
            "/api/v1/status/business-entities/{businessId}/status-list-entries/{statusListId}";
    private static final String UPDATE_PATH_V2 =
            "/api/v2/status/business-entities/{businessId}/status-list-entries/{statusListId}";
    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder().build();
    private static final String STATUSLIST_URI_PATTERN = "https://" + MockServices.MOCKSERVER_HOST + "/api/v1/statuslist/%s.jwt";
    private static final String DEFAULT_COMPRESSED_STATUSES = "eNrtwQEBAAAAgiD_r25IQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHwYYagAAQ";

    private final RegisteredActors actors;

    /** What a Credential Issuer published for a status list: the {@code bits} and the {@code lst} of its Status List Token. */
    private record PublishedStatusList(int bits, String compressedStatuses) {
    }

    private static final PublishedStatusList EMPTY_LIST = new PublishedStatusList(2, DEFAULT_COMPRESSED_STATUSES);

    private final Map<String, PublishedStatusList> publishedStatusLists = new ConcurrentHashMap<>();
    private final Map<String, String> statusListsByIssuerDid = new ConcurrentHashMap<>();
    private final Map<String, String> issuerDidByStatusListId = new ConcurrentHashMap<>();
    private volatile String currentStatusList = "";
    private volatile String activeIssuerDid = "";
    private volatile boolean throwStatusListError = false;
    private volatile boolean corruptStatusListSignature = false;

    StatusRegistry(final RegisteredActors actors) {
        this.actors = actors;
    }

    void enableUpdateError() {
        this.throwStatusListError = true;
        log.debug("Status list error mode ENABLED - subsequent PUT requests will fail");
    }

    void disableUpdateError() {
        this.throwStatusListError = false;
        log.debug("Status list error mode DISABLED");
    }

    void enableCorruptSignature() {
        this.corruptStatusListSignature = true;
        log.debug("Status list signature corruption ENABLED");
    }

    void disableCorruptSignature() {
        this.corruptStatusListSignature = false;
        log.debug("Status list signature corruption DISABLED");
    }

    void resetFaults() {
        disableUpdateError();
        disableCorruptSignature();
    }

    boolean updatesFail() {
        return throwStatusListError;
    }

    boolean servesCorruptSignature() {
        return corruptStatusListSignature;
    }

    /** Tells the registry that {@code issuerDid} owns the status list {@code statusListId}, so it signs it with its key. */
    void issuerOwns(final String statusListId, final String issuerDid) {
        issuerDidByStatusListId.put(statusListId, issuerDid);
    }

    /**
     * A status list entry was created for the Business Entity {@code businessId}: it belongs to the issuer registered with
     * that SWIYU partner id. A creation for an unknown Business Entity leaves the list without an owner.
     */
    void onStatusListCreated(final String businessId, final String statusListId) {
        actors.issuerByPartnerId(businessId).ifPresent(issuer -> issuerOwns(statusListId, issuer.getIssuerDid()));
    }

    /** The Credential Issuer published a Status List Token for {@code statusListId}: keep its {@code bits} and {@code lst}. */
    void onStatusListPublished(final String statusListId, final String statusListTokenJwt) {
        final PublishedStatusList published = parsePublished(statusListTokenJwt);
        if (published != null && statusListId != null) {
            publishedStatusLists.put(statusListId, published);
        }
    }

    /**
     * The Status List Token to serve for {@code statusListId}, signed by the issuer that owns the list, or empty when no
     * issuer owns it: an unknown list is a {@code 404}, not a list signed by whichever issuer the mock knows first.
     */
    Optional<String> statusListToken(final String statusListId) {
        final String issuerDid = issuerDidByStatusListId.get(statusListId);
        if (issuerDid == null) {
            return Optional.empty();
        }
        return actors.issuer(issuerDid).map(issuer -> signedStatusListToken(statusListId, issuer));
    }

    void setCurrent(final String issuerDid, final String statusList) {
        currentStatusList = statusList;
        activeIssuerDid = issuerDid;
        statusListsByIssuerDid.put(issuerDid, statusList);
        final String statusListId = extractStatusListIdFromPath(statusList);
        if (statusListId != null) {
            issuerOwns(statusListId, issuerDid);
        }
    }

    /** The status list a renewal response must carry: the one of the requested issuer, else of the active one. */
    String currentRenewalStatusList(final HttpRequest httpRequest) {
        final String requestedIssuerDid = httpRequest.getFirstQueryStringParameter("issuerDid");
        if (requestedIssuerDid != null && !requestedIssuerDid.isBlank()) {
            final String statusList = statusListsByIssuerDid.get(requestedIssuerDid);
            if (statusList != null) {
                return statusList;
            }
        }
        if (activeIssuerDid != null && !activeIssuerDid.isBlank()) {
            final String statusList = statusListsByIssuerDid.get(activeIssuerDid);
            if (statusList != null) {
                return statusList;
            }
        }
        return currentStatusList;
    }

    void registerRoutes(final MockServerClient mockServerClient) {
        // Keep credential UUIDs disjoint from TP2 paths: clearing a TP2 route must not match this expectation.
        mockServerClient.when(
                request()
                    .withMethod("GET")
                    .withPath("/api/v1/statuslist/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                            + "[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\.jwt"))
                .respond(httpRequest -> {
                    log.info("Entered GET expectation for status list retrieval with path: {}", httpRequest.getPath().getValue());
                    return statusListToken(extractStatusListIdFromPath(httpRequest.getPath().getValue()))
                            .map(token -> response()
                                    .withHeader(CONTENT_TYPE, "application/statuslist+jwt")
                                    .withStatusCode(HttpStatusCode.OK_200.code())
                                    .withBody(token))
                            .orElseGet(() -> response().withStatusCode(HttpStatusCode.NOT_FOUND_404.code()));
                });
        mockServerClient.when(
                request()
                        .withMethod("POST")
                        .withPath("/api/v1/status/business-entities/{businessId}/status-list-entries/")
                        .withPathParameter("businessId", ".*"))
                .respond(httpRequest -> {
                    log.info("Entered POST expectation for status list creation with path: {}", httpRequest.getPath().getValue());
                    var id = UUID.randomUUID();
                    onStatusListCreated(businessIdFromPath(httpRequest.getPath().getValue()), id.toString());
                    var payload = "{\"id\": \"%s\", \"statusRegistryUrl\": \"%s\"}"
                            .formatted(id, STATUSLIST_URI_PATTERN.formatted(id));
                    return response()
                            .withStatusCode(200)
                            .withHeader(CONTENT_TYPE, "application/json")
                            .withBody(payload);
                });
        mockServerClient.when(request().withMethod("PUT").withPath(UPDATE_PATH_V1)
                .withPathParameter("businessId", ".*").withPathParameter("statusListId", ".*"))
                .respond(httpRequest -> updateResponse(httpRequest, false));
        mockServerClient.when(request().withMethod("PUT").withPath(UPDATE_PATH_V2)
                .withPathParameter("businessId", ".*").withPathParameter("statusListId", ".*"))
                .respond(httpRequest -> updateResponse(httpRequest, true));
    }

    /**
     * The answer to the upload of a Status List Token. v1 accepts it with a {@code 202}, as it always did. v2 rejects a token
     * that is not conformant to the Swiss profile with a {@code 400} and an {@code ApiError} listing the violations, and
     * accepts it with a {@code 200} (operation {@code updateStatusListEntry} of {@code SWIYU_Core_Business_status.yaml}).
     */
    private HttpResponse updateResponse(final HttpRequest httpRequest, final boolean enforceSwissProfile) {
        log.info("Entered PUT expectation (Swiss profile enforced: {}) for status list update with path: {}",
                enforceSwissProfile, httpRequest.getPath().getValue());

        if (throwStatusListError) {
            log.debug("Status list error mode enabled - returning 500 error");
            return response()
                    .withStatusCode(500)
                    .withHeader(CONTENT_TYPE, "application/json")
                    .withBody("{\"error\": \"Internal server error - status list update failed\"}");
        }

        if (enforceSwissProfile) {
            final List<String> violations = SwissStatusListConformity.violations(compactJwt(httpRequest.getBodyAsString()));
            if (!violations.isEmpty()) {
                log.warn("Status list token rejected, it violates the Swiss profile: {}", violations);
                return response()
                        .withStatusCode(400)
                        .withHeader(CONTENT_TYPE, "application/json")
                        .withBody(apiError(violations));
            }
        }

        try {
            final String path = httpRequest.getPath().getValue();
            final String statusListId = extractStatusListIdFromPath(path);

            onStatusListPublished(statusListId, httpRequest.getBodyAsString());
        } catch (Exception e) {
            return response().withStatusCode(500);
        }
        return response().withStatusCode(enforceSwissProfile ? 200 : 202);
    }

    /** The {@code ApiError} of the Status Registry: {@code data_invalid} is "the given data was invalid in syntax or semantic". */
    private static String apiError(final List<String> violations) {
        return OBJECT_MAPPER.writeValueAsString(Map.of(
                "errorCode", "data_invalid",
                "message", "The status list token does not conform to the Swiss profile",
                "additionalDetails", violations));
    }

    private String signedStatusListToken(final String statusListId, final IssuerConfig issuerConfig) {
        try {
            final JWK jwk = KeyUtil.createJWKFromKeyPair(issuerConfig.getKeyPair());
            final JWSSigner signer = new ECDSASigner(jwk.toECKey());

            final PublishedStatusList published = publishedStatusLists.getOrDefault(statusListId, EMPTY_LIST);
            final Date issuedAt = new Date();

            final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(STATUSLIST_URI_PATTERN.formatted(statusListId))
                    .issuer(issuerConfig.getIssuerDid())
                    .issueTime(issuedAt)
                    .claim("status_list", Map.of(
                            "bits", published.bits(),
                            "lst", published.compressedStatuses()))
                    .expirationTime(new Date(issuedAt.getTime() + 60 * 1000))
                    .build();

            final SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .keyID(issuerConfig.getIssuerAssertKeyId())
                            .type(new JOSEObjectType("statuslist+jwt"))
                            .build(),
                    claimsSet);

            signedJWT.sign(signer);

            final String serializedStatusList = signedJWT.serialize();
            return corruptStatusListSignature
                    ? corruptJwtSignature(serializedStatusList)
                    : serializedStatusList;
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot sign the status list token", e);
        }
    }

    private static String corruptJwtSignature(final String jwt) {
        final String[] parts = jwt.split("\\.", -1);
        if (parts.length != 3 || parts[2].isEmpty()) {
            throw new IllegalArgumentException("JWT must be a compact JWS with a signature");
        }

        final char replacement = parts[2].charAt(0) == 'A' ? 'B' : 'A';
        parts[2] = replacement + parts[2].substring(1);
        return String.join(".", parts);
    }

    private static String extractStatusListIdFromPath(final String path) {
        if (path == null) return null;

        final int lastSlash = path.lastIndexOf('/');
        if (lastSlash < 0) return null;

        final String lastSegment = path.substring(lastSlash + 1);

        if (lastSegment.endsWith(".jwt")) {
            return lastSegment.substring(0, lastSegment.length() - 4);
        }

        return lastSegment;
    }

    /**
     * The {@code bits} and {@code lst} of a Status List Token received in a PUT (Token Status List draft 20 §4.2). The body is
     * the JWT itself or its base64 encoding. Returns {@code null} when it is not a Status List Token.
     */
    private static PublishedStatusList parsePublished(final String jwtBody) {
        try {
            if (jwtBody == null || jwtBody.isEmpty()) {
                return null;
            }

            final SignedJWT jwt = SignedJWT.parse(compactJwt(jwtBody));
            final Map<String, Object> claims = jwt.getJWTClaimsSet().getClaims();

            if (claims.get("status_list") instanceof Map<?, ?> statusListClaim && statusListClaim.get("lst") instanceof String lst) {
                final Object bits = statusListClaim.get("bits");
                return new PublishedStatusList(bits == null ? EMPTY_LIST.bits() : Integer.parseInt(bits.toString()), lst);
            }
        } catch (ParseException | NumberFormatException e) {
            return null;
        }
        return null;
    }

    /** The upload body is the Status List Token itself or its base64 encoding. */
    private static String compactJwt(final String body) {
        if (body == null) {
            return null;
        }
        try {
            return new String(Base64.getDecoder().decode(body));
        } catch (IllegalArgumentException e) {
            return body;
        }
    }

    /** {@code .../business-entities/<businessId>/status-list-entries/...}: the Business Entity of the request. */
    private static String businessIdFromPath(final String path) {
        final String marker = "/business-entities/";
        final int start = path.indexOf(marker);
        if (start < 0) {
            return null;
        }
        final String rest = path.substring(start + marker.length());
        final int end = rest.indexOf('/');
        return end < 0 ? rest : rest.substring(0, end);
    }
}
