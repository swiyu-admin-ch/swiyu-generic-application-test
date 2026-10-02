package ch.admin.bj.swiyu.swiyu_test_wallet.mock;

import ch.admin.bj.swiyu.gen.issuer.model.WebhookCallback;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockAttestationAuthority;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.TrustConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.mock.tp2.Tp2TrustRegistryMockServerConfigurer;
import com.nimbusds.jose.JOSEException;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.ClearType;
import org.testcontainers.containers.MockServerContainer;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;

import static org.mockserver.model.HttpRequest.request;

/**
 * The external services of the swiyu ecosystem, simulated by one MockServer: the Base Registry (DID logs), the Status
 * Registry, the OAuth token endpoint, the webhook callback sinks, the renewal service, the first-generation trust service,
 * and the Trust Protocol 2.0 registry ({@code mock.tp2}).
 *
 * <p>This class is the entry point the environment and the tests use. Each service is a class of its own in this package;
 * they share the actors registered here ({@code RegisteredActors}).
 */
public class MockServices {

    @SuppressWarnings("java:S1075") // Constant URI is intentional: used only in test/support context
    public static final String ISSUER_CALLBACK_PATH = "/callbacks/issuer";
    @SuppressWarnings("java:S1075") // Constant URI is intentional: used only in test/support context
    public static final String VERIFIER_CALLBACK_PATH = "/callbacks/verifier";
    public static final String MOCKSERVER_HOST = "mockserver:1080";
    public static final String UNTRUSTED_REGISTRY_HOST = "untrusted-registry:1080";
    private static final List<String> TP2_ROUTE_PATTERNS = List.of(
            "/api/v2/identity-trust-statement.*",
            "/api/v2/verification-query-public-statement.*",
            "/api/v1/trust/vqps-submissions/?",
            "/api/v2/protected-verification-authorization-trust-statement.*",
            "/api/v2/protected-issuance-authorization-trust-statement.*",
            "/api/v2/protected-issuance-trust-list-statement.*",
            "/api/v2/protected-issuance-trust-list/?",
            "/api/v2/non-compliance-trust-list/?",
            "/api/v1/statuslist/tp2-trust-statements\\.jwt"
    );
    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .disable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    private final RegisteredActors actors = new RegisteredActors();
    private final DidLogRegistry didLogs = new DidLogRegistry();
    private final StatusRegistry statusRegistry = new StatusRegistry(actors);
    private final CallbackSink callbackSink = new CallbackSink();
    private final OAuthTokenStub oauthToken = new OAuthTokenStub();
    private final RenewalService renewalService = new RenewalService(statusRegistry);
    private final LegacyTrustStatements legacyTrustStatements = new LegacyTrustStatements(actors);

    public List<WebhookCallback> getIssuerCallbacks() {
        return callbackSink.issuerCallbacks();
    }

    public void clearIssuerCallbacks() {
        callbackSink.clearIssuerCallbacks();
    }

    public void enableStatusListError() {
        statusRegistry.enableUpdateError();
    }

    public void disableStatusListError() {
        statusRegistry.disableUpdateError();
    }

    public void enableCorruptStatusListSignature() {
        statusRegistry.enableCorruptSignature();
    }

    public void disableCorruptStatusListSignature() {
        statusRegistry.disableCorruptSignature();
    }

    /** Puts every simulated service back to its normal behavior; {@code BaseTest} does it after each test. */
    public void resetFaults() {
        statusRegistry.resetFaults();
    }

    public MockServerClient createMockServerClient(MockServerContainer mockServer,
            IssuerConfig issuerConfig,
            VerifierConfig verifierConfig,
            TrustConfig trustConfig,
            MockAttestationAuthority attestationAuthority) {
        registerIssuer(issuerConfig);
        registerVerifier(verifierConfig);
        registerTrust(trustConfig);
        registerAttestationAuthority(attestationAuthority);
        final MockServerClient mockServerClient = createMockServerClient(mockServer, trustConfig, attestationAuthority);
        registerTp2Routes(mockServerClient, issuerConfig, verifierConfig, trustConfig);
        return mockServerClient;
    }

    public MockServerClient createMockServerClient(MockServerContainer mockServer,
                                                   TrustConfig trustConfig,
                                                   MockAttestationAuthority attestationAuthority) {
        registerTrust(trustConfig);
        registerAttestationAuthority(attestationAuthority);

        final MockServerClient mockServerClient = new MockServerClient(
                mockServer.getHost(),
                mockServer.getServerPort());

        statusRegistry.registerRoutes(mockServerClient);
        didLogs.registerRoutes(mockServerClient);
        oauthToken.registerRoutes(mockServerClient);
        callbackSink.registerRoutes(mockServerClient);
        renewalService.registerRoutes(mockServerClient);
        legacyTrustStatements.registerRoutes(mockServerClient);

        return mockServerClient;
    }

    public void registerIssuer(final IssuerConfig issuerConfig) {
        actors.addIssuer(issuerConfig);
        didLogs.register(issuerConfig.getIssuerDid(), issuerConfig.getIssuerDidLog());
        issuerConfig.getAdditionalSigningIdentities().forEach(this::registerIssuer);
    }

    public void registerVerifier(final VerifierConfig verifierConfig) {
        actors.addVerifier(verifierConfig);
        didLogs.register(verifierConfig.getVerifierDid(), verifierConfig.getVerifierDidLog());
        verifierConfig.getAdditionalSigningIdentities().forEach(this::registerVerifier);
    }

    public void registerTrust(final TrustConfig trustConfig) {
        actors.trustConfig(trustConfig);
        didLogs.register(trustConfig.getTrustDid(), trustConfig.getTrustDidLog());
    }

    public void registerAttestationAuthority(final MockAttestationAuthority attestationAuthority) {
        actors.attestationAuthority(attestationAuthority);
        if (attestationAuthority != null) {
            didLogs.register(attestationAuthority.getDid(), attestationAuthority.getDidLog());
        }
    }

    public void replaceDidLog(final String did, final String didLog) {
        didLogs.register(did, didLog);
    }

    public void registerTp2Routes(final MockServerClient mockServerClient,
                                  final IssuerConfig issuerConfig,
                                  final VerifierConfig verifierConfig,
                                  final TrustConfig trustConfig) {
        clearTp2Routes(mockServerClient);
        Tp2TrustRegistryMockServerConfigurer.registerRoutes(
                mockServerClient,
                issuerConfig,
                verifierConfig,
                trustConfig,
                OBJECT_MAPPER
        );
    }

    public String createLegacyIssuanceTrustStatement(final String vct, final IssuerConfig issuerConfig) {
        try {
            return legacyTrustStatements.issuanceStatement(vct, issuerConfig);
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot generate legacy issuance trust statement", e);
        }
    }

    private void clearTp2Routes(final MockServerClient mockServerClient) {
        TP2_ROUTE_PATTERNS.forEach(path ->
                mockServerClient.clear(request().withPath(path), ClearType.EXPECTATIONS)
        );
    }

    public void setCurrentStatusList(final String issuerDid, final String statusList) {
        statusRegistry.setCurrent(issuerDid, statusList);
    }
}
