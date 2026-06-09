package ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.TrustConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.mockserver.client.MockServerClient;
import org.mockserver.matchers.TimeToLive;
import org.mockserver.matchers.Times;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

import static org.mockserver.model.HttpRequest.request;

public final class Tp2TrustRegistryMockServerConfigurer {

    private static final String IDENTITY_TRUST_STATEMENT_PATH = "/api/v2/identity-trust-statement";
    private static final String VERIFICATION_QUERY_PUBLIC_STATEMENT_PATH =
            "/api/v2/verification-query-public-statement";
    private static final String VQPS_SUBMISSION_PATH = "/api/v1/trust/vqps-submissions";
    private static final String PROTECTED_VERIFICATION_AUTHORIZATION_PATH =
            "/api/v2/protected-verification-authorization-trust-statement";
    private static final String PROTECTED_ISSUANCE_AUTHORIZATION_PATH =
            "/api/v2/protected-issuance-authorization-trust-statement";
    private static final String PROTECTED_ISSUANCE_TRUST_LIST_STATEMENT_PATH =
            "/api/v2/protected-issuance-trust-list-statement";
    private static final String PROTECTED_ISSUANCE_TRUST_LIST_PATH = "/api/v2/protected-issuance-trust-list";
    private static final String NON_COMPLIANCE_TRUST_LIST_PATH = "/api/v2/non-compliance-trust-list";
    private static final String TP2_STATUS_LIST_PATH = "/api/v1/statuslist/tp2-trust-statements.jwt";
    private static final String MOCK_OAUTH_ACCESS_TOKEN = "access_token";
    private static final String TRUST_REGISTRY_CUSTOMER_KEY = "SWIYU_TRUST_REGISTRY_CUSTOMER_KEY";
    private static final String TRUST_REGISTRY_CUSTOMER_SECRET = "SWIYU_TRUST_REGISTRY_CUSTOMER_SECRET";
    private static final String EXPECTED_TRUST_REGISTRY_BASIC_AUTHORIZATION =
            "Basic " + Base64.getEncoder().encodeToString(
                    (TRUST_REGISTRY_CUSTOMER_KEY + ":" + TRUST_REGISTRY_CUSTOMER_SECRET)
                            .getBytes(StandardCharsets.UTF_8)
            );

    private Tp2TrustRegistryMockServerConfigurer() {
    }

    public static void registerRoutes(MockServerClient mockServerClient,
                                      IssuerConfig issuerConfig,
                                      VerifierConfig verifierConfig,
                                      TrustConfig trustConfig,
                                      ObjectMapper objectMapper) {
        Tp2TrustRegistryStatementFactory statementFactory = new Tp2TrustRegistryStatementFactory(
                issuerConfig,
                verifierConfig,
                trustConfig
        );
        Tp2MockServerResponseFactory responseFactory = new Tp2MockServerResponseFactory(objectMapper);

        registerIdentityTrustStatementRoutes(mockServerClient, statementFactory, responseFactory);
        registerVerificationQueryPublicStatementRoutes(mockServerClient, statementFactory, responseFactory);
        registerProtectedVerificationAuthorizationRoutes(mockServerClient, statementFactory, responseFactory);
        registerProtectedIssuanceAuthorizationRoutes(mockServerClient, statementFactory, responseFactory);
        registerProtectedIssuanceTrustListRoutes(mockServerClient, statementFactory, responseFactory);
        registerNonComplianceTrustListRoute(mockServerClient, statementFactory, responseFactory);
        registerTrustStatementStatusListRoute(mockServerClient, statementFactory, responseFactory);
    }

    public static void registerIssuerTrustStatementRoutes(MockServerClient mockServerClient,
                                                          IssuerConfig issuerConfig,
                                                          TrustConfig trustConfig,
                                                          ObjectMapper objectMapper) {
        Tp2TrustRegistryStatementFactory statementFactory = new Tp2TrustRegistryStatementFactory(
                issuerConfig,
                trustConfig
        );
        Tp2MockServerResponseFactory responseFactory = new Tp2MockServerResponseFactory(objectMapper);

        registerIdentityTrustStatementRoutes(mockServerClient, statementFactory, responseFactory);
        registerProtectedIssuanceAuthorizationRoutes(mockServerClient, statementFactory, responseFactory);
    }

    private static void registerIdentityTrustStatementRoutes(MockServerClient mockServerClient,
                                                             Tp2TrustRegistryStatementFactory statementFactory,
                                                             Tp2MockServerResponseFactory responseFactory) {
        mockServerClient.when(request().withMethod("GET").withPath(IDENTITY_TRUST_STATEMENT_PATH + "/?"))
                .respond(httpRequest -> {
                    HttpResponse authorizationError = validateTrustRegistryBasicAuth(httpRequest, responseFactory);
                    if (authorizationError != null) {
                        return authorizationError;
                    }

                    HttpResponse validationError = validateListRouteRequest(httpRequest, responseFactory, true);
                    if (validationError != null) {
                        return validationError;
                    }

                    return responseFactory.jsonResponse(
                            responseFactory.pagedContent(
                                    statementFactory.buildIdentityTrustStatements(requestedSubject(httpRequest)),
                                    httpRequest
                            )
                    );
                });

        mockServerClient.when(request().withMethod("GET").withPath(IDENTITY_TRUST_STATEMENT_PATH + "/.+"))
                .respond(httpRequest -> {
                    HttpResponse authorizationError = validateTrustRegistryBasicAuth(httpRequest, responseFactory);
                    if (authorizationError != null) {
                        return authorizationError;
                    }

                    final String identifier = extractLastPathSegment(httpRequest);
                    if (!statementFactory.isKnownIdentitySubject(identifier)) {
                        return responseFactory.notFoundResponse("No identity trust statement found for identifier");
                    }
                    return responseFactory.jwtResponse(statementFactory.buildIdentityTrustStatement(identifier));
                });
    }

    private static void registerVerificationQueryPublicStatementRoutes(MockServerClient mockServerClient,
                                                                       Tp2TrustRegistryStatementFactory statementFactory,
                                                                       Tp2MockServerResponseFactory responseFactory) {
        mockServerClient.when(request().withMethod("POST").withPath(VQPS_SUBMISSION_PATH + "/?"))
                .respond(httpRequest -> {
                    final String authorization = httpRequest.getFirstHeader("Authorization");
                    if (!("Bearer " + MOCK_OAUTH_ACCESS_TOKEN).equals(authorization)) {
                        return responseFactory.unauthorizedResponse("OAuth access token is required");
                    }

                    try {
                        final String vqPs = statementFactory.publishVerificationQueryPublicStatementFromRegistration(
                                responseFactory.requestBodyAsMap(httpRequest)
                        ).jwt();
                        return responseFactory.vqpsSubmissionSuccessResponse(vqPs);
                    } catch (IllegalArgumentException e) {
                        return responseFactory.tmsValidationErrorResponse(
                                "Invalid DCQL syntax.",
                                "query",
                                e.getMessage()
                        );
                    }
                });

        mockServerClient.when(request().withMethod("GET").withPath(VERIFICATION_QUERY_PUBLIC_STATEMENT_PATH + "/?"))
                .respond(httpRequest -> {
                    HttpResponse validationError = validateListRouteRequest(httpRequest, responseFactory, true);
                    if (validationError != null) {
                        return validationError;
                    }

                    return responseFactory.jsonResponse(
                            responseFactory.pagedContent(
                                    statementFactory.buildVerificationQueryPublicStatements(requestedSubject(httpRequest)),
                                    httpRequest
                            )
                    );
                });

        mockServerClient.when(request().withMethod("GET").withPath(VERIFICATION_QUERY_PUBLIC_STATEMENT_PATH + "/.+"))
                .respond(httpRequest -> {
                    final String jti = extractLastPathSegment(httpRequest);
                    if (!isUuidV4(jti)) {
                        return responseFactory.badRequestResponse("jti must be a UUIDv4");
                    }
                    return statementFactory.findVerificationQueryPublicStatement(jti)
                            .map(responseFactory::jwtResponse)
                            .orElseGet(() -> responseFactory.notFoundResponse(
                                    "No verification query public statement found for jti"
                            ));
                });
    }

    private static void registerProtectedVerificationAuthorizationRoutes(MockServerClient mockServerClient,
                                                                         Tp2TrustRegistryStatementFactory statementFactory,
                                                                         Tp2MockServerResponseFactory responseFactory) {
        mockServerClient.when(request().withMethod("GET").withPath(PROTECTED_VERIFICATION_AUTHORIZATION_PATH + "/?"))
                .respond(httpRequest -> {
                    HttpResponse validationError = validateListRouteRequest(httpRequest, responseFactory, true);
                    if (validationError != null) {
                        return validationError;
                    }

                    return responseFactory.jsonResponse(
                            responseFactory.pagedContent(
                                    statementFactory.buildProtectedVerificationAuthorizationStatements(
                                            requestedSubject(httpRequest)
                                    ),
                                    httpRequest
                            )
                    );
                });

        mockServerClient.when(request().withMethod("GET").withPath(PROTECTED_VERIFICATION_AUTHORIZATION_PATH + "/.+"))
                .respond(httpRequest -> {
                    final String jti = extractLastPathSegment(httpRequest);
                    if (!isUuidV4(jti)) {
                        return responseFactory.badRequestResponse("jti must be a UUIDv4");
                    }
                    if (!statementFactory.isKnownProtectedVerificationAuthorizationStatementJti(jti)) {
                        return responseFactory.notFoundResponse(
                                "No protected verification authorization trust statement found for jti"
                        );
                    }
                    return responseFactory.jwtResponse(statementFactory.buildProtectedVerificationAuthorizationStatement(
                            statementFactory.defaultVerifierSubject(),
                            jti
                    ));
                });
    }

    private static void registerProtectedIssuanceAuthorizationRoutes(MockServerClient mockServerClient,
                                                                     Tp2TrustRegistryStatementFactory statementFactory,
                                                                     Tp2MockServerResponseFactory responseFactory) {
        mockServerClient.when(request().withMethod("GET").withPath(PROTECTED_ISSUANCE_AUTHORIZATION_PATH + "/?"))
                .respond(httpRequest -> {
                    HttpResponse authorizationError = validateTrustRegistryBasicAuth(httpRequest, responseFactory);
                    if (authorizationError != null) {
                        return authorizationError;
                    }

                    HttpResponse validationError = validateListRouteRequest(httpRequest, responseFactory, true);
                    if (validationError != null) {
                        return validationError;
                    }

                    return responseFactory.jsonResponse(
                            responseFactory.pagedContent(
                                    statementFactory.buildProtectedIssuanceAuthorizationStatements(
                                            requestedSubject(httpRequest)
                                    ),
                                    httpRequest
                            )
                    );
                });

        mockServerClient.when(request().withMethod("GET").withPath(PROTECTED_ISSUANCE_AUTHORIZATION_PATH + "/.+"))
                .respond(httpRequest -> {
                    HttpResponse authorizationError = validateTrustRegistryBasicAuth(httpRequest, responseFactory);
                    if (authorizationError != null) {
                        return authorizationError;
                    }

                    final String jti = extractLastPathSegment(httpRequest);
                    if (!isUuidV4(jti)) {
                        return responseFactory.badRequestResponse("jti must be a UUIDv4");
                    }
                    if (!statementFactory.isKnownProtectedIssuanceAuthorizationStatementJti(jti)) {
                        return responseFactory.notFoundResponse(
                                "No protected issuance authorization trust statement found for jti"
                        );
                    }
                    return responseFactory.jwtResponse(statementFactory.buildProtectedIssuanceAuthorizationStatement(
                            statementFactory.issuerSubject(),
                            jti
                    ));
                });
    }

    private static void registerProtectedIssuanceTrustListRoutes(MockServerClient mockServerClient,
                                                                 Tp2TrustRegistryStatementFactory statementFactory,
                                                                 Tp2MockServerResponseFactory responseFactory) {
        mockServerClient.when(request().withMethod("GET").withPath(PROTECTED_ISSUANCE_TRUST_LIST_STATEMENT_PATH + "/?"))
                .respond(httpRequest -> {
                    HttpResponse validationError = validateListRouteRequest(httpRequest, responseFactory, false);
                    if (validationError != null) {
                        return validationError;
                    }

                    return responseFactory.jsonResponse(
                            responseFactory.pagedContent(
                                    statementFactory.buildProtectedIssuanceTrustListStatements(),
                                    httpRequest
                            )
                    );
                });

        mockServerClient.when(request().withMethod("GET").withPath(PROTECTED_ISSUANCE_TRUST_LIST_STATEMENT_PATH + "/.+"))
                .respond(httpRequest -> {
                    final String jti = extractLastPathSegment(httpRequest);
                    if (!isUuidV4(jti)) {
                        return responseFactory.badRequestResponse("jti must be a UUIDv4");
                    }
                    if (!statementFactory.isKnownProtectedIssuanceTrustListStatementJti(jti)) {
                        return responseFactory.notFoundResponse(
                                "No protected issuance trust list statement found for jti"
                        );
                    }
                    return responseFactory.jwtResponse(statementFactory.buildProtectedIssuanceTrustListStatement(jti));
                });

        mockServerClient.when(request().withMethod("GET").withPath(PROTECTED_ISSUANCE_TRUST_LIST_PATH + "/?"))
                .respond(httpRequest -> responseFactory.jwtResponse(statementFactory.buildProtectedIssuanceTrustList()));
    }

    private static void registerNonComplianceTrustListRoute(MockServerClient mockServerClient,
                                                            Tp2TrustRegistryStatementFactory statementFactory,
                                                            Tp2MockServerResponseFactory responseFactory) {
        mockServerClient.when(request().withMethod("GET").withPath(NON_COMPLIANCE_TRUST_LIST_PATH + "/?"))
                .respond(httpRequest -> responseFactory.jwtResponse(statementFactory.buildNonComplianceTrustList()));
    }

    private static void registerTrustStatementStatusListRoute(MockServerClient mockServerClient,
                                                              Tp2TrustRegistryStatementFactory statementFactory,
                                                              Tp2MockServerResponseFactory responseFactory) {
        mockServerClient.when(
                        request().withMethod("GET").withPath(TP2_STATUS_LIST_PATH),
                        Times.unlimited(),
                        TimeToLive.unlimited(),
                        10
                )
                .respond(httpRequest -> responseFactory.statusListJwtResponse(statementFactory.buildTrustStatusListJwt()));
    }

    private static HttpResponse validateTrustRegistryBasicAuth(HttpRequest httpRequest,
                                                              Tp2MockServerResponseFactory responseFactory) {
        final String authorization = httpRequest.getFirstHeader("Authorization");
        if (!EXPECTED_TRUST_REGISTRY_BASIC_AUTHORIZATION.equals(authorization)) {
            return responseFactory.unauthorizedResponse("Trust Registry Basic Auth credentials are required");
        }
        return null;
    }

    private static HttpResponse validateListRouteRequest(HttpRequest httpRequest,
                                                         Tp2MockServerResponseFactory responseFactory,
                                                         boolean allowSubjectFilter) {
        if (!allowSubjectFilter && queryParameter(httpRequest, "sub") != null) {
            return responseFactory.badRequestResponse("sub is not supported for this endpoint");
        }
        if (!isValidBooleanParameter(queryParameter(httpRequest, "filterActive"))) {
            return responseFactory.badRequestResponse("filterActive must be a boolean");
        }
        if (!isValidIntegerParameter(queryParameter(httpRequest, "page"), 0)) {
            return responseFactory.badRequestResponse("page must be a non-negative integer");
        }
        if (!isValidIntegerParameter(queryParameter(httpRequest, "size"), 1)) {
            return responseFactory.badRequestResponse("size must be a positive integer");
        }
        return null;
    }

    private static String requestedSubject(HttpRequest httpRequest) {
        return queryParameter(httpRequest, "sub");
    }

    private static String extractLastPathSegment(HttpRequest httpRequest) {
        final String path = httpRequest.getPath().getValue();
        final int lastSlash = path.lastIndexOf('/');
        if (lastSlash < 0 || lastSlash == path.length() - 1) {
            return path;
        }
        return java.net.URLDecoder.decode(path.substring(lastSlash + 1), StandardCharsets.UTF_8);
    }

    private static boolean isUuidV4(String value) {
        try {
            return UUID.fromString(value).version() == 4;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static boolean isValidBooleanParameter(String value) {
        return value == null || "true".equalsIgnoreCase(value) || "false".equalsIgnoreCase(value);
    }

    private static boolean isValidIntegerParameter(String value, int minimumValue) {
        if (value == null) {
            return true;
        }
        try {
            return Integer.parseInt(value) >= minimumValue;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static String queryParameter(HttpRequest httpRequest, String name) {
        final String value = httpRequest.getFirstQueryStringParameter(name);
        return value == null || value.isBlank() ? null : value;
    }
}
