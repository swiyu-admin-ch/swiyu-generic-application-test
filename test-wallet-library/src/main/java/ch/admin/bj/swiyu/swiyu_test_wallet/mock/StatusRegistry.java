package ch.admin.bj.swiyu.swiyu_test_wallet.mock;

import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpStatusCode;

import java.text.ParseException;
import java.util.Date;
import java.util.Map;
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
 * <p>It can be told to fail updates or to serve a token with a corrupted signature, for the tests that need a faulty
 * registry.
 */
@Slf4j
final class StatusRegistry {

    private static final String STATUSLIST_URI_PATTERN = "https://" + MockServices.MOCKSERVER_HOST + "/api/v1/statuslist/%s.jwt";
    private static final String DEFAULT_COMPRESSED_STATUSES = "eNrtwQEBAAAAgiD_r25IQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHwYYagAAQ";

    private final RegisteredActors actors;

    private final Map<String, String> statusListBitsMap = new ConcurrentHashMap<>();
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

    void setCurrent(final String issuerDid, final String statusList) {
        currentStatusList = statusList;
        activeIssuerDid = issuerDid;
        statusListsByIssuerDid.put(issuerDid, statusList);
        final String statusListId = extractStatusListIdFromPath(statusList);
        if (statusListId != null) {
            issuerDidByStatusListId.put(statusListId, issuerDid);
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
                    return response()
                            .withHeader(CONTENT_TYPE, "application/statuslist+jwt")
                            .withStatusCode(HttpStatusCode.OK_200.code())
                            .withBody(statusListJwt(httpRequest, issuerConfigForStatusList(httpRequest)));
                });
        mockServerClient.when(
                request()
                        .withMethod("POST")
                        .withPath("/api/v1/status/business-entities/{businessId}/status-list-entries/")
                        .withPathParameter("businessId", ".*"))
                .respond(httpRequest -> {
                    log.info("Entered POST expectation for status list creation with path: {}", httpRequest.getPath().getValue());
                    var id = UUID.randomUUID();
                    var payload = "{\"id\": \"%s\", \"statusRegistryUrl\": \"%s\"}"
                            .formatted(id, STATUSLIST_URI_PATTERN.formatted(id));
                    return response()
                            .withStatusCode(200)
                            .withHeader(CONTENT_TYPE, "application/json")
                            .withBody(payload);
                });
        mockServerClient.when(request().withMethod("PUT").withPath(
                "/api/v1/status/business-entities/{businessId}/status-list-entries/{statusListId}")
                .withPathParameter("businessId", ".*").withPathParameter("statusListId", ".*"))
                .respond(httpRequest -> {
                    log.info("Entered PUT expectation for status list update with path: {}", httpRequest.getPath().getValue());

                    if (throwStatusListError) {
                        log.debug("Status list error mode enabled - returning 500 error");
                        return response()
                                .withStatusCode(500)
                                .withHeader(CONTENT_TYPE, "application/json")
                                .withBody("{\"error\": \"Internal server error - status list update failed\"}");
                    }

                    try {
                        final String path = httpRequest.getPath().getValue();
                        final String statusListId = extractStatusListIdFromPath(path);

                        final String jwtBody = httpRequest.getBodyAsString();
                        final String compressedStatuses = extractCompressedStatusesFromJwt(jwtBody);

                        if (compressedStatuses != null && statusListId != null) {
                            statusListBitsMap.put(statusListId, compressedStatuses);
                        }
                    } catch (Exception e) {
                        return response().withStatusCode(500);
                    }
                    return response().withStatusCode(202);
                });
    }

    private IssuerConfig issuerConfigForStatusList(final HttpRequest httpRequest) {
        final String statusListId = extractStatusListIdFromPath(httpRequest.getPath().getValue());
        if (statusListId == null) {
            return actors.anyIssuer();
        }

        final String issuerDid = issuerDidByStatusListId.get(statusListId);
        if (issuerDid == null) {
            return actors.anyIssuer();
        }

        return actors.issuer(issuerDid).orElseGet(actors::anyIssuer);
    }

    private String statusListJwt(final HttpRequest httpRequest, final IssuerConfig issuerConfig)
            throws JOSEException, ParseException {

        final JWK jwk = KeyUtil.createJWKFromKeyPair(issuerConfig.getKeyPair());

        final JWSSigner signer = new ECDSASigner(jwk.toECKey());

        final String path = httpRequest.getPath().getValue();
        final String statusListId = extractStatusListIdFromPath(path);

        final String compressedStatuses = statusListBitsMap.getOrDefault(statusListId, DEFAULT_COMPRESSED_STATUSES);
        final Date issuedAt = new Date();

        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(STATUSLIST_URI_PATTERN.formatted(statusListId))
                .issuer(issuerConfig.getIssuerDid())
                .issueTime(issuedAt)
                .claim("status_list", Map.of(
                        "bits", "2",
                        "lst", compressedStatuses))
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

    /** The {@code lst} of a Status List Token received in a PUT: the base64url compressed byte array (Token Status List §4.1). */
    private static String extractCompressedStatusesFromJwt(final String jwtBody) {
        try {
            if (jwtBody == null || jwtBody.isEmpty()) {
                return null;
            }

            String decodedBody;
            try {
                byte[] decoded = java.util.Base64.getDecoder().decode(jwtBody);
                decodedBody = new String(decoded);
            } catch (IllegalArgumentException e) {
                decodedBody = jwtBody;
            }

            final SignedJWT jwt = SignedJWT.parse(decodedBody);
            final Map<String, Object> claims = jwt.getJWTClaimsSet().getClaims();

            if (claims.containsKey("status_list")) {
                @SuppressWarnings("unchecked")
                final Map<String, Object> statusListClaim = (Map<String, Object>) claims.get("status_list");
                return (String) statusListClaim.get("lst");
            }
        } catch (ParseException e) {
            return null;
        }
        return null;
    }
}
