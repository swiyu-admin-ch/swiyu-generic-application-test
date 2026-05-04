package ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.TrustConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.mockserver.model.HttpRequest.request;

public final class Tp2TrustRegistryMockServerConfigurer {

    private static final String IDENTITY_TRUST_STATEMENT_PATH = "/api/v2/identity-trust-statement";
    private static final String VERIFICATION_QUERY_PUBLIC_STATEMENT_PATH =
            "/api/v2/verification-query-public-statement";
    private static final String PROTECTED_VERIFICATION_AUTHORIZATION_PATH =
            "/api/v2/protected-verification-authorization-trust-statement";
    private static final String PROTECTED_ISSUANCE_AUTHORIZATION_PATH =
            "/api/v2/protected-issuance-authorization-trust-statement";
    private static final String PROTECTED_ISSUANCE_TRUST_LIST_STATEMENT_PATH =
            "/api/v2/protected-issuance-trust-list-statement";
    private static final String PROTECTED_ISSUANCE_TRUST_LIST_PATH = "/api/v2/protected-issuance-trust-list";
    private static final String NON_COMPLIANCE_TRUST_LIST_PATH = "/api/v2/non-compliance-trust-list";

    private Tp2TrustRegistryMockServerConfigurer() {
    }

    public static void registerRoutes(MockServerClient mockServerClient,
                                      IssuerConfig issuerConfig,
                                      TrustConfig trustConfig,
                                      ObjectMapper objectMapper) {
        Tp2TrustRegistryStatementFactory statementFactory = new Tp2TrustRegistryStatementFactory(
                issuerConfig,
                trustConfig
        );
        Tp2MockServerResponseFactory responseFactory = new Tp2MockServerResponseFactory(objectMapper);

        registerIdentityTrustStatementRoutes(mockServerClient, statementFactory, responseFactory);
        registerVerificationQueryPublicStatementRoutes(mockServerClient, statementFactory, responseFactory);
        registerProtectedVerificationAuthorizationRoutes(mockServerClient, statementFactory, responseFactory);
        registerProtectedIssuanceAuthorizationRoutes(mockServerClient, statementFactory, responseFactory);
        registerProtectedIssuanceTrustListRoutes(mockServerClient, statementFactory, responseFactory);
        registerNonComplianceTrustListRoute(mockServerClient, statementFactory, responseFactory);
    }

    private static void registerIdentityTrustStatementRoutes(MockServerClient mockServerClient,
                                                             Tp2TrustRegistryStatementFactory statementFactory,
                                                             Tp2MockServerResponseFactory responseFactory) {
        mockServerClient.when(request().withMethod("GET").withPath(IDENTITY_TRUST_STATEMENT_PATH))
                .respond(httpRequest -> responseFactory.jsonResponse(
                        responseFactory.pagedContent(
                                statementFactory.buildIdentityTrustStatements(resolveRequestedSubject(httpRequest)),
                                httpRequest
                        )
                ));

        mockServerClient.when(request().withMethod("GET").withPath(IDENTITY_TRUST_STATEMENT_PATH + "/.*"))
                .respond(httpRequest -> responseFactory.jwtResponse(
                        statementFactory.buildIdentityTrustStatement(extractLastPathSegment(httpRequest))
                ));
    }

    private static void registerVerificationQueryPublicStatementRoutes(MockServerClient mockServerClient,
                                                                       Tp2TrustRegistryStatementFactory statementFactory,
                                                                       Tp2MockServerResponseFactory responseFactory) {
        mockServerClient.when(request().withMethod("GET").withPath(VERIFICATION_QUERY_PUBLIC_STATEMENT_PATH))
                .respond(httpRequest -> responseFactory.jsonResponse(
                        responseFactory.pagedContent(
                                List.of(statementFactory.buildVerificationQueryPublicStatement(
                                        statementFactory.resolveVerifierSubject(httpRequest.getFirstQueryStringParameter("sub")),
                                        statementFactory.verificationQueryPublicJti()
                                )),
                                httpRequest
                        )
                ));

        mockServerClient.when(request().withMethod("GET").withPath(VERIFICATION_QUERY_PUBLIC_STATEMENT_PATH + "/.*"))
                .respond(httpRequest -> responseFactory.jwtResponse(
                        statementFactory.buildVerificationQueryPublicStatement(
                                statementFactory.defaultVerifierSubject(),
                                extractLastPathSegment(httpRequest)
                        )
                ));
    }

    private static void registerProtectedVerificationAuthorizationRoutes(MockServerClient mockServerClient,
                                                                         Tp2TrustRegistryStatementFactory statementFactory,
                                                                         Tp2MockServerResponseFactory responseFactory) {
        mockServerClient.when(request().withMethod("GET").withPath(PROTECTED_VERIFICATION_AUTHORIZATION_PATH))
                .respond(httpRequest -> responseFactory.jsonResponse(
                        responseFactory.pagedContent(
                                List.of(statementFactory.buildProtectedVerificationAuthorizationStatement(
                                        statementFactory.resolveVerifierSubject(httpRequest.getFirstQueryStringParameter("sub")),
                                        statementFactory.protectedVerificationAuthorizationJti()
                                )),
                                httpRequest
                        )
                ));

        mockServerClient.when(request().withMethod("GET").withPath(PROTECTED_VERIFICATION_AUTHORIZATION_PATH + "/.*"))
                .respond(httpRequest -> responseFactory.jwtResponse(
                        statementFactory.buildProtectedVerificationAuthorizationStatement(
                                statementFactory.defaultVerifierSubject(),
                                extractLastPathSegment(httpRequest)
                        )
                ));
    }

    private static void registerProtectedIssuanceAuthorizationRoutes(MockServerClient mockServerClient,
                                                                     Tp2TrustRegistryStatementFactory statementFactory,
                                                                     Tp2MockServerResponseFactory responseFactory) {
        mockServerClient.when(request().withMethod("GET").withPath(PROTECTED_ISSUANCE_AUTHORIZATION_PATH))
                .respond(httpRequest -> responseFactory.jsonResponse(
                        responseFactory.pagedContent(
                                List.of(statementFactory.buildProtectedIssuanceAuthorizationStatement(
                                        statementFactory.resolveIssuerSubject(httpRequest.getFirstQueryStringParameter("sub")),
                                        statementFactory.protectedIssuanceAuthorizationJti()
                                )),
                                httpRequest
                        )
                ));

        mockServerClient.when(request().withMethod("GET").withPath(PROTECTED_ISSUANCE_AUTHORIZATION_PATH + "/.*"))
                .respond(httpRequest -> responseFactory.jwtResponse(
                        statementFactory.buildProtectedIssuanceAuthorizationStatement(
                                statementFactory.issuerSubject(),
                                extractLastPathSegment(httpRequest)
                        )
                ));
    }

    private static void registerProtectedIssuanceTrustListRoutes(MockServerClient mockServerClient,
                                                                 Tp2TrustRegistryStatementFactory statementFactory,
                                                                 Tp2MockServerResponseFactory responseFactory) {
        mockServerClient.when(request().withMethod("GET").withPath(PROTECTED_ISSUANCE_TRUST_LIST_STATEMENT_PATH))
                .respond(httpRequest -> responseFactory.jsonResponse(
                        responseFactory.pagedContent(
                                List.of(statementFactory.buildProtectedIssuanceTrustListStatement(
                                        statementFactory.protectedIssuanceTrustListJti()
                                )),
                                httpRequest
                        )
                ));

        mockServerClient.when(request().withMethod("GET").withPath(PROTECTED_ISSUANCE_TRUST_LIST_STATEMENT_PATH + "/.*"))
                .respond(httpRequest -> responseFactory.jwtResponse(
                        statementFactory.buildProtectedIssuanceTrustListStatement(extractLastPathSegment(httpRequest))
                ));

        mockServerClient.when(request().withMethod("GET").withPath(PROTECTED_ISSUANCE_TRUST_LIST_PATH))
                .respond(httpRequest -> responseFactory.jsonResponse(statementFactory.buildProtectedIssuanceTrustList()));
    }

    private static void registerNonComplianceTrustListRoute(MockServerClient mockServerClient,
                                                            Tp2TrustRegistryStatementFactory statementFactory,
                                                            Tp2MockServerResponseFactory responseFactory) {
        mockServerClient.when(request().withMethod("GET").withPath(NON_COMPLIANCE_TRUST_LIST_PATH))
                .respond(httpRequest -> responseFactory.jsonResponse(statementFactory.buildNonComplianceTrustList()));
    }

    private static String resolveRequestedSubject(HttpRequest httpRequest) {
        final String requestedSubject = httpRequest.getFirstQueryStringParameter("sub");
        return requestedSubject == null || requestedSubject.isBlank() ? null : requestedSubject;
    }

    private static String extractLastPathSegment(HttpRequest httpRequest) {
        final String path = httpRequest.getPath().getValue();
        final int lastSlash = path.lastIndexOf('/');
        if (lastSlash < 0 || lastSlash == path.length() - 1) {
            return path;
        }
        return java.net.URLDecoder.decode(path.substring(lastSlash + 1), StandardCharsets.UTF_8);
    }
}
