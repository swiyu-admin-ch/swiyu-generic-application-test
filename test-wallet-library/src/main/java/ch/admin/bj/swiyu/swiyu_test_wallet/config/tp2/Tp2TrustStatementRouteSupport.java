package ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.TrustConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.TestSupportException;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import tools.jackson.databind.ObjectMapper;
import org.mockserver.client.MockServerClient;
import org.mockserver.matchers.TimeToLive;
import org.mockserver.matchers.Times;
import org.mockserver.model.ClearType;
import org.mockserver.model.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

/**
 * Scenario-level TP2 routes for generic application e2e tests.
 *
 * <p>The default TP2 mock registry intentionally exposes only the configured issuer/verifier.
 * Cache tests need dynamic DIDs, short lifetimes, mismatched VCTs, and transient failures. This
 * helper keeps that behavior in one place while still using the shared statement factory.</p>
 */
public final class Tp2TrustStatementRouteSupport {

    public enum IssuerTrustStatementTarget {
        IDENTITY,
        PROTECTED_ISSUANCE_AUTHORIZATION
    }

    private enum SignatureMutation {
        NONE,
        TAMPERED_PAYLOAD,
        TAMPERED_SIGNATURE,
        WRONG_KEY,
        ALG_NONE
    }

    public static final String IDENTITY_TRUST_STATEMENT_PATH = "/api/v2/identity-trust-statement";
    public static final String PROTECTED_ISSUANCE_AUTHORIZATION_PATH =
            "/api/v2/protected-issuance-authorization-trust-statement";
    public static final String PROTECTED_VERIFICATION_AUTHORIZATION_PATH =
            "/api/v2/protected-verification-authorization-trust-statement";
    public static final String VERIFICATION_QUERY_PUBLIC_STATEMENT_PATH =
            "/api/v2/verification-query-public-statement";
    public static final String VERIFICATION_QUERY_PUBLIC_STATEMENT_SUBMISSION_PATH =
            "/api/v1/trust/vqps-submissions";
    public static final String PROTECTED_VCT = Tp2TrustRegistryStatementFactory.TP2_PROTECTED_VCT;
    public static final String TP2_PROFILE_VERSION = Tp2TrustRegistryStatementFactory.TP2_PROFILE_VERSION;

    private final MockServerClient mockServerClient;
    private final Tp2TrustRegistryStatementFactory statementFactory;
    private final Tp2MockServerResponseFactory responseFactory;

    public Tp2TrustStatementRouteSupport(MockServerClient mockServerClient,
                                         IssuerConfig issuerConfig,
                                         VerifierConfig verifierConfig,
                                         TrustConfig trustConfig,
                                         ObjectMapper objectMapper) {
        this(
                mockServerClient,
                issuerConfig,
                verifierConfig,
                trustConfig,
                objectMapper,
                Tp2TrustStatementAlgorithm.ES256
        );
    }

    public Tp2TrustStatementRouteSupport(MockServerClient mockServerClient,
                                         IssuerConfig issuerConfig,
                                         VerifierConfig verifierConfig,
                                         TrustConfig trustConfig,
                                         ObjectMapper objectMapper,
                                         Tp2TrustStatementAlgorithm signatureAlgorithm) {
        this.mockServerClient = mockServerClient;
        this.statementFactory = new Tp2TrustRegistryStatementFactory(
                issuerConfig,
                verifierConfig,
                trustConfig,
                signatureAlgorithm
        );
        this.responseFactory = new Tp2MockServerResponseFactory(objectMapper);
    }

    public void registerIssuerSuccess(Duration lifetime) {
        registerIssuerSuccess(lifetime, PROTECTED_VCT);
    }

    public void registerIssuerSuccess(Duration lifetime, String piaTsVct) {
        clearIssuerRoutes();
        registerIdentityRoute(lifetime, SignatureMutation.NONE, null);
        registerPiaTsRoute(lifetime, piaTsVct, SignatureMutation.NONE, null);
    }

    public void registerIssuerTamperedPayload(Duration lifetime, IssuerTrustStatementTarget target) {
        registerIssuerInvalid(lifetime, SignatureMutation.TAMPERED_PAYLOAD, target);
    }

    public void registerIssuerWrongKey(Duration lifetime, IssuerTrustStatementTarget target) {
        registerIssuerInvalid(lifetime, SignatureMutation.WRONG_KEY, target);
    }

    public void registerIssuerAlgorithmNone(Duration lifetime) {
        clearIssuerRoutes();
        registerIdentityRoute(lifetime, SignatureMutation.ALG_NONE, null);
        registerPiaTsRoute(lifetime, PROTECTED_VCT, SignatureMutation.ALG_NONE, null);
    }

    public void registerIssuerTransientErrorThenSuccess(Duration lifetime) {
        clearIssuerRoutes();
        registerIdentityRoute(lifetime, SignatureMutation.NONE, new AtomicInteger());
        registerPiaTsRoute(lifetime, PROTECTED_VCT, SignatureMutation.NONE, new AtomicInteger());
    }

    public void registerVerifierSuccess(Duration lifetime) {
        clearVerifierRoutes();
        registerIdentityRoute(lifetime, SignatureMutation.NONE, null);
        registerPvaTsRoute(lifetime, SignatureMutation.NONE, null);
        registerVqPsRoute(lifetime, null);
    }

    public void registerVerifierInvalidIdentity(Duration lifetime) {
        clearVerifierRoutes();
        registerIdentityRoute(lifetime, SignatureMutation.TAMPERED_SIGNATURE, null);
        registerPvaTsRoute(lifetime, SignatureMutation.NONE, null);
        registerVqPsRoute(lifetime, null);
    }

    public void registerVerifierTransientErrorThenSuccess(Duration lifetime) {
        clearVerifierRoutes();
        registerIdentityRoute(lifetime, SignatureMutation.NONE, new AtomicInteger());
        registerPvaTsRoute(lifetime, SignatureMutation.NONE, new AtomicInteger());
        registerVqPsRoute(lifetime, new AtomicInteger());
    }

    public void restoreDefaults(IssuerConfig issuerConfig,
                                VerifierConfig verifierConfig,
                                TrustConfig trustConfig,
                                ObjectMapper objectMapper) {
        clearIssuerRoutes();
        clearVerifierRoutes();
        Tp2TrustRegistryMockServerConfigurer.registerRoutes(
                mockServerClient,
                issuerConfig,
                verifierConfig,
                trustConfig,
                objectMapper
        );
    }

    public void clearIssuerRoutes() {
        mockServerClient.clear(
                request().withMethod("GET").withPath(IDENTITY_TRUST_STATEMENT_PATH + "/?"),
                ClearType.EXPECTATIONS
        );
        mockServerClient.clear(
                request().withMethod("GET").withPath(IDENTITY_TRUST_STATEMENT_PATH + "/.+"),
                ClearType.EXPECTATIONS
        );
        mockServerClient.clear(
                request().withMethod("GET").withPath(PROTECTED_ISSUANCE_AUTHORIZATION_PATH + "/?"),
                ClearType.EXPECTATIONS
        );
    }

    public void clearVerifierRoutes() {
        mockServerClient.clear(
                request().withMethod("GET").withPath(IDENTITY_TRUST_STATEMENT_PATH + "/?"),
                ClearType.EXPECTATIONS
        );
        mockServerClient.clear(
                request().withMethod("GET").withPath(IDENTITY_TRUST_STATEMENT_PATH + "/.+"),
                ClearType.EXPECTATIONS
        );
        mockServerClient.clear(
                request().withMethod("GET").withPath(PROTECTED_VERIFICATION_AUTHORIZATION_PATH + "/?"),
                ClearType.EXPECTATIONS
        );
        mockServerClient.clear(
                request().withMethod("GET").withPath(VERIFICATION_QUERY_PUBLIC_STATEMENT_PATH + "/?"),
                ClearType.EXPECTATIONS
        );
        mockServerClient.clear(
                request().withMethod("GET").withPath(VERIFICATION_QUERY_PUBLIC_STATEMENT_PATH + "/.+"),
                ClearType.EXPECTATIONS
        );
    }

    public int identityTrustStatementRequests() {
        return recordedGetRequests(IDENTITY_TRUST_STATEMENT_PATH + "/?")
                + recordedGetRequests(IDENTITY_TRUST_STATEMENT_PATH + "/.+");
    }

    public int identityTrustStatementRequests(String subject) {
        return recordedGetRequestsWithQuerySubject(IDENTITY_TRUST_STATEMENT_PATH + "/?", subject)
                + recordedGetRequestsWithPathSubject(IDENTITY_TRUST_STATEMENT_PATH + "/.+", subject);
    }

    public int protectedIssuanceAuthorizationRequests() {
        return recordedGetRequests(PROTECTED_ISSUANCE_AUTHORIZATION_PATH + "/?");
    }

    public int protectedIssuanceAuthorizationRequests(String subject) {
        return recordedGetRequestsWithQuerySubject(PROTECTED_ISSUANCE_AUTHORIZATION_PATH + "/?", subject);
    }

    public int protectedVerificationAuthorizationRequests() {
        return recordedGetRequests(PROTECTED_VERIFICATION_AUTHORIZATION_PATH + "/?");
    }

    public int protectedVerificationAuthorizationRequests(String subject) {
        return recordedGetRequestsWithQuerySubject(PROTECTED_VERIFICATION_AUTHORIZATION_PATH + "/?", subject);
    }

    public int verificationQueryPublicStatementSubmissions() {
        return mockServerClient.retrieveRecordedRequests(
                request().withMethod("POST").withPath(VERIFICATION_QUERY_PUBLIC_STATEMENT_SUBMISSION_PATH + "/?")
        ).length;
    }

    private void registerIssuerInvalid(Duration lifetime,
                                       SignatureMutation mutation,
                                       IssuerTrustStatementTarget target) {
        clearIssuerRoutes();
        registerIdentityRoute(
                lifetime,
                target == IssuerTrustStatementTarget.IDENTITY ? mutation : SignatureMutation.NONE,
                null
        );
        registerPiaTsRoute(
                lifetime,
                PROTECTED_VCT,
                target == IssuerTrustStatementTarget.PROTECTED_ISSUANCE_AUTHORIZATION
                        ? mutation
                        : SignatureMutation.NONE,
                null
        );
    }

    private void registerIdentityRoute(Duration lifetime,
                                       SignatureMutation mutation,
                                       AtomicInteger transientFailures) {
        mockServerClient.when(
                        request().withMethod("GET").withPath(IDENTITY_TRUST_STATEMENT_PATH + "/?"),
                        Times.unlimited(),
                        TimeToLive.unlimited(),
                        100
                )
                .respond(httpRequest -> {
                    if (shouldFailOnce(transientFailures)) {
                        return response()
                                .withStatusCode(503)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"error\":\"temporary idTS fetch failure\"}");
                    }

                    String subject = httpRequest.getFirstQueryStringParameter("sub");
                    if (subject == null || subject.isBlank()) {
                        subject = statementFactory.issuerSubject();
                    }
                    String jwt = statementFactory.buildIdentityTrustStatement(subject, lifetime);
                    return responseFactory.jsonResponse(responseFactory.pagedContent(
                            List.of(mutateJwt(jwt, mutation)),
                            httpRequest
                    ));
                });

        mockServerClient.when(
                        request().withMethod("GET").withPath(IDENTITY_TRUST_STATEMENT_PATH + "/.+"),
                        Times.unlimited(),
                        TimeToLive.unlimited(),
                        100
                )
                .respond(httpRequest -> {
                    if (shouldFailOnce(transientFailures)) {
                        return response()
                                .withStatusCode(503)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"error\":\"temporary idTS fetch failure\"}");
                    }

                    String jwt = statementFactory.buildIdentityTrustStatement(extractLastPathSegment(httpRequest), lifetime);
                    return responseFactory.jwtResponse(mutateJwt(jwt, mutation));
                });
    }

    private void registerPiaTsRoute(Duration lifetime,
                                    String vct,
                                    SignatureMutation mutation,
                                    AtomicInteger transientFailures) {
        mockServerClient.when(
                        request().withMethod("GET").withPath(PROTECTED_ISSUANCE_AUTHORIZATION_PATH + "/?"),
                        Times.unlimited(),
                        TimeToLive.unlimited(),
                        100
                )
                .respond(httpRequest -> {
                    if (shouldFailOnce(transientFailures)) {
                        return response()
                                .withStatusCode(503)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"error\":\"temporary piaTS fetch failure\"}");
                    }

                    String subject = httpRequest.getFirstQueryStringParameter("sub");
                    String jwt = statementFactory.buildProtectedIssuanceAuthorizationStatement(
                            subject,
                            UUID.randomUUID().toString(),
                            lifetime,
                            vct
                    );
                    return responseFactory.jsonResponse(pagedContent(mutateJwt(jwt, mutation)));
                });
    }

    private void registerPvaTsRoute(Duration lifetime,
                                    SignatureMutation mutation,
                                    AtomicInteger transientFailures) {
        mockServerClient.when(
                        request().withMethod("GET").withPath(PROTECTED_VERIFICATION_AUTHORIZATION_PATH + "/?"),
                        Times.unlimited(),
                        TimeToLive.unlimited(),
                        100
                )
                .respond(httpRequest -> {
                    if (shouldFailOnce(transientFailures)) {
                        return response()
                                .withStatusCode(503)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"error\":\"temporary pvaTS fetch failure\"}");
                    }

                    String subject = httpRequest.getFirstQueryStringParameter("sub");
                    String jwt = statementFactory.buildProtectedVerificationAuthorizationStatement(
                            subject,
                            UUID.randomUUID().toString(),
                            lifetime
                    );
                    return responseFactory.jsonResponse(pagedContent(mutateJwt(jwt, mutation)));
                });
    }

    private void registerVqPsRoute(Duration lifetime, AtomicInteger transientFailures) {
        mockServerClient.when(
                        request().withMethod("GET").withPath(VERIFICATION_QUERY_PUBLIC_STATEMENT_PATH + "/?"),
                        Times.unlimited(),
                        TimeToLive.unlimited(),
                        100
                )
                .respond(httpRequest -> {
                    if (shouldFailOnce(transientFailures)) {
                        return response()
                                .withStatusCode(503)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"error\":\"temporary vqPS fetch failure\"}");
                    }

                    String subject = httpRequest.getFirstQueryStringParameter("sub");
                    if (subject == null || subject.isBlank()) {
                        return responseFactory.jsonResponse(pagedContent());
                    }

                    String jwt = statementFactory.buildVerificationQueryPublicStatement(
                            subject,
                            UUID.randomUUID().toString(),
                            lifetime
                    );
                    return responseFactory.jsonResponse(pagedContent(jwt));
                });
    }

    private boolean shouldFailOnce(AtomicInteger attempts) {
        return attempts != null && attempts.getAndIncrement() == 0;
    }

    private Map<String, Object> pagedContent(String... jwts) {
        List<String> content = List.of(jwts);
        return Map.of(
                "content", content,
                "page", Map.of(
                        "size", content.size(),
                        "number", 0,
                        "totalPages", content.isEmpty() ? 0 : 1,
                        "totalElements", content.size()
                )
        );
    }

    private int recordedGetRequests(String path) {
        return mockServerClient.retrieveRecordedRequests(
                request().withMethod("GET").withPath(path)
        ).length;
    }

    private int recordedGetRequestsWithQuerySubject(String path, String subject) {
        return (int) Arrays.stream(mockServerClient.retrieveRecordedRequests(
                        request().withMethod("GET").withPath(path)
                ))
                .filter(recordedRequest -> subject.equals(
                        recordedRequest.getFirstQueryStringParameter("sub")
                ))
                .count();
    }

    private int recordedGetRequestsWithPathSubject(String path, String subject) {
        return (int) Arrays.stream(mockServerClient.retrieveRecordedRequests(
                        request().withMethod("GET").withPath(path)
                ))
                .filter(recordedRequest -> subject.equals(extractLastPathSegment(recordedRequest)))
                .count();
    }

    private String mutateJwt(String jwt, SignatureMutation mutation) {
        return switch (mutation) {
            case NONE -> jwt;
            case TAMPERED_PAYLOAD -> tamperJwtPayload(jwt);
            case TAMPERED_SIGNATURE -> tamperJwtSignature(jwt);
            case WRONG_KEY -> statementFactory.resignWithUntrustedKey(jwt);
            case ALG_NONE -> unsecuredJwt(jwt);
        };
    }

    private String tamperJwtPayload(String jwt) {
        try {
            SignedJWT parsed = SignedJWT.parse(jwt);
            JWTClaimsSet tamperedClaims = new JWTClaimsSet.Builder(parsed.getJWTClaimsSet())
                    .claim("tampered", true)
                    .build();
            String[] parts = jwt.split("\\.", -1);
            return parts[0] + "." + Base64URL.encode(tamperedClaims.toString()) + "." + parts[2];
        } catch (ParseException e) {
            throw new TestSupportException("Cannot tamper TP2 trust-statement payload: " + e.getMessage());
        }
    }

    private String tamperJwtSignature(String jwt) {
        String[] parts = jwt.split("\\.", -1);
        char replacement = parts[2].charAt(0) == 'A' ? 'B' : 'A';
        parts[2] = replacement + parts[2].substring(1);
        return String.join(".", parts);
    }

    static String unsecuredJwt(String jwt) {
        try {
            SignedJWT parsed = SignedJWT.parse(jwt);
            Map<String, Object> customParams = new HashMap<>(parsed.getHeader().getCustomParams());
            customParams.put("kid", parsed.getHeader().getKeyID());
            PlainHeader header = new PlainHeader.Builder()
                    .type(parsed.getHeader().getType())
                    .customParams(customParams)
                    .build();
            return new PlainJWT(header, parsed.getJWTClaimsSet()).serialize();
        } catch (ParseException e) {
            throw new TestSupportException("Cannot create alg=none TP2 trust statement: " + e.getMessage());
        }
    }

    private String extractLastPathSegment(HttpRequest httpRequest) {
        final String path = httpRequest.getPath().getValue();
        final int lastSlash = path.lastIndexOf('/');
        if (lastSlash < 0 || lastSlash == path.length() - 1) {
            return path;
        }
        return java.net.URLDecoder.decode(path.substring(lastSlash + 1), StandardCharsets.UTF_8);
    }
}
