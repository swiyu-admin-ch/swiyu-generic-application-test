package ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.TrustConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.mockserver.client.MockServerClient;
import org.mockserver.matchers.TimeToLive;
import org.mockserver.matchers.Times;
import org.mockserver.model.ClearType;
import org.mockserver.model.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
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
        this.mockServerClient = mockServerClient;
        this.statementFactory = new Tp2TrustRegistryStatementFactory(issuerConfig, verifierConfig, trustConfig);
        this.responseFactory = new Tp2MockServerResponseFactory(objectMapper);
    }

    public void registerIssuerSuccess(Duration lifetime) {
        registerIssuerSuccess(lifetime, PROTECTED_VCT);
    }

    public void registerIssuerSuccess(Duration lifetime, String piaTsVct) {
        clearIssuerRoutes();
        registerIdentityRoute(lifetime, false, null);
        registerPiaTsRoute(lifetime, piaTsVct, null);
    }

    public void registerIssuerTransientErrorThenSuccess(Duration lifetime) {
        clearIssuerRoutes();
        registerIdentityRoute(lifetime, false, new AtomicInteger());
        registerPiaTsRoute(lifetime, PROTECTED_VCT, new AtomicInteger());
    }

    public void registerVerifierSuccess(Duration lifetime) {
        clearVerifierRoutes();
        registerIdentityRoute(lifetime, false, null);
        registerPvaTsRoute(lifetime, false, null);
        registerVqPsRoute(lifetime, null);
    }

    public void registerVerifierInvalidIdentity(Duration lifetime) {
        clearVerifierRoutes();
        registerIdentityRoute(lifetime, true, null);
        registerPvaTsRoute(lifetime, false, null);
        registerVqPsRoute(lifetime, null);
    }

    public void registerVerifierTransientErrorThenSuccess(Duration lifetime) {
        clearVerifierRoutes();
        registerIdentityRoute(lifetime, false, new AtomicInteger());
        registerPvaTsRoute(lifetime, false, new AtomicInteger());
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

    public int protectedIssuanceAuthorizationRequests() {
        return recordedGetRequests(PROTECTED_ISSUANCE_AUTHORIZATION_PATH + "/?");
    }

    public int protectedVerificationAuthorizationRequests() {
        return recordedGetRequests(PROTECTED_VERIFICATION_AUTHORIZATION_PATH + "/?");
    }

    public int verificationQueryPublicStatementSubmissions() {
        return mockServerClient.retrieveRecordedRequests(
                request().withMethod("POST").withPath(VERIFICATION_QUERY_PUBLIC_STATEMENT_SUBMISSION_PATH + "/?")
        ).length;
    }

    private void registerIdentityRoute(Duration lifetime, boolean tamperSignature, AtomicInteger transientFailures) {
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
                            List.of(tamperSignature ? tamperJwtSignature(jwt) : jwt),
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
                    return responseFactory.jwtResponse(tamperSignature ? tamperJwtSignature(jwt) : jwt);
                });
    }

    private void registerPiaTsRoute(Duration lifetime, String vct, AtomicInteger transientFailures) {
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
                    return responseFactory.jsonResponse(pagedContent(jwt));
                });
    }

    private void registerPvaTsRoute(Duration lifetime, boolean tamperSignature, AtomicInteger transientFailures) {
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
                    return responseFactory.jsonResponse(pagedContent(tamperSignature ? tamperJwtSignature(jwt) : jwt));
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

    private String tamperJwtSignature(String jwt) {
        return jwt + "A";
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
