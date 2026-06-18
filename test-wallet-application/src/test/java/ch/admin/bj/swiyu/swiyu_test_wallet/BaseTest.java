package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.gen.issuer.model.WebhookCallback;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerHandle;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.SwiyuEnvironmentRegistry;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.SwiyuEnvironmentSelection;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierHandle;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuanceService;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.HttpTraceInterceptor;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.*;
import org.mockserver.client.MockServerClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.io.File;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntSupplier;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig.ISSUER_CALLBACK_PATH;
import static ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig.VERIFIER_CALLBACK_PATH;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockserver.model.HttpRequest.request;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
        classes = SwiyuTestWalletApplication.class
)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@Slf4j
@SuppressWarnings({
        // This class is a shared test infrastructure base:
        // it intentionally centralizes setup, wiring, and utilities for integration tests.
        // Design-related PMD rules (size, coupling, imports, generic exceptions) are not relevant here
        // and would reduce readability and reuse if strictly enforced.
        "PMD.SignatureDeclareThrowsException",
        "PMD.TooManyFields",
        "PMD.TooManyMethods",
        "PMD.TestClassWithoutTestCases",
        "PMD.CouplingBetweenObjects",
        "PMD.ExcessiveImports",
        "java:S2187" // Base class for tests - does not contain test methods itself
})
public class BaseTest {

    @Autowired
    protected ApplicationTestConfig applicationTestConfig;
    @Autowired
    protected IssuerImageConfig issuerImageConfig;
    @Autowired
    protected VerifierImageConfig verifierImageConfig;
    @Autowired
    protected ManagementAuthConfig managementAuthConfig;
    @Autowired
    protected SwiyuEnvironmentRegistry environmentRegistry;
    protected TrustConfig trustConfig;
    protected GenericContainer<?> issuerContainer;
    protected GenericContainer<?> verifierContainer;
    protected PostgreSQLContainer<?> dbTestContainer;
    protected MockServerContainer mockServerContainer;
    @Autowired
    protected MockServerClientConfig mockServerClientConfig;
    protected MockAttestationAuthority mockAttestationAuthority;
    protected IssuerConfig issuerConfig;
    protected VerifierConfig verifierConfig;
    protected MockServerClient mockServerClient;

    protected Connection connection;
    protected Wallet wallet;
    @Getter private StatusList currentStatusList;
    @Getter protected IssuerHandle currentIssuer;
    @Getter protected VerifierHandle currentVerifier;
    protected BusinessIssuer issuerManager;
    protected IssuanceService issuanceService;
    protected VerifierManager verifierManager;
    protected RestClient restClient;
    protected Statement stmt;
    protected PrivateKey jwtKey;
    protected String keyId = "test-key-1";
    protected PrivateKey unauthenticatedJwtKey;
    protected String issuerManagementAccessToken;
    protected String verifierManagementAccessToken;
    private File traceFile;
    private final Map<String, AtomicInteger> invocationCounters = new HashMap<>();

    @BeforeEach
    protected void resetIssuerCallbacks() {
        mockServerClientConfig.clearIssuerCallbacks();
    }

    protected void cleanIssuerCallbacks() {
        awaitStableIssuerCallbacks();
        mockServerClientConfig.clearIssuerCallbacks();
    }

    protected List<WebhookCallback> issuerCallbacks() {
        return mockServerClientConfig.getIssuerCallbacks();
    }

    protected void setCurrentStatusList(StatusList currentStatusList) {
        if (currentStatusList == null) {
            throw new IllegalArgumentException("currentStatusList cannot be null");
        }
        this.currentStatusList = currentStatusList;
        mockServerClientConfig.setCurrentStatusList(
                issuerConfig.getIssuerDid(),
                String.valueOf(currentStatusList.getStatusRegistryUrl())
        );
    }

    protected int countVerifierCallbacks() {
        return mockServerClient
                .retrieveRecordedRequests(request().withPath(VERIFIER_CALLBACK_PATH))
                .length;
    }

    protected int countIssuerCallbacks() {
        return mockServerClient
                .retrieveRecordedRequests(request().withPath(ISSUER_CALLBACK_PATH))
                .length;
    }

    protected int awaitStableVerifierCallbacks() {
        return awaitStableCount(this::countVerifierCallbacks);
    }

    protected int awaitStableIssuerCallbacks() {
        return awaitStableCount(this::countIssuerCallbacks);
    }

    protected void awaitNVerifierCallback(final int before, final int n) {
        await().untilAsserted(() ->
                assertThat(countVerifierCallbacks())
                        .isEqualTo(before + n)
        );
    }

    protected void awaitOneVerifierCallback(final int before) {
        awaitNVerifierCallback(before, 1);
    }

    protected void awaitNoneVerifierCallback(final int before) {
        awaitNVerifierCallback(before, 0);
    }

    protected void awaitNIssuerCallback(final int before, final int n) {
        await().untilAsserted(() ->
                assertThat(countIssuerCallbacks())
                        .isEqualTo(before + n)
        );
    }

    protected void awaitOneIssuerCallback(final int before) {
        awaitNIssuerCallback(before, 1);
    }

    protected void awaitNoneIssuerCallback(final int before) {
        awaitNIssuerCallback(before, 0);
    }

    protected String swiyuDidVariant(final String did) {
        final int lastColon = did.lastIndexOf(":");
        return did.substring(0, lastColon + 1) + UUID.randomUUID();
    }

    protected int awaitStableCount(final IntSupplier counter) {
        final AtomicInteger previous = new AtomicInteger(-1);

        await()
                .pollInterval(Duration.ofMillis(250))
                .atMost(Duration.ofSeconds(3))
                .until(() -> {
                    int current = counter.getAsInt();
                    int last = previous.getAndSet(current);
                    return last == current;
                });

        return previous.get();
    }

    @BeforeAll
    void setup() throws Exception {
        final SwiyuEnvironmentSelection selection = SwiyuEnvironmentSelection.from(getClass());
        environmentRegistry.ensureStarted(selection);
        selection.issuers().forEach(environmentRegistry::refreshStatusList);

        dbTestContainer = environmentRegistry.dbContainer();
        mockServerContainer = environmentRegistry.mockServerContainer();
        mockServerClient = environmentRegistry.mockServerClient();
        trustConfig = environmentRegistry.trustConfig();
        mockAttestationAuthority = environmentRegistry.mockAttestationAuthority();

        restClient = RestClient.builder().build();

        final IssuerHandle primaryIssuer = issuer(selection.primaryIssuer());
        final VerifierHandle primaryVerifier = verifier(selection.primaryVerifier());
        wallet = new Wallet(restClient, primaryIssuer.serviceLocation(), primaryVerifier.serviceLocation());
        useComponents(primaryIssuer, primaryVerifier);

        connection = DriverManager.getConnection(
                dbTestContainer.getJdbcUrl(),
                dbTestContainer.getUsername(),
                dbTestContainer.getPassword()
        );
        stmt = connection.createStatement();
    }

    protected IssuerHandle issuer(final IssuerVariant variant) {
        return environmentRegistry.issuer(variant);
    }

    protected VerifierHandle verifier(final VerifierVariant variant) {
        return environmentRegistry.verifier(variant);
    }

    protected void useIssuer(final IssuerHandle issuer) {
        currentIssuer = issuer;
        issuerConfig = issuer.config();
        issuerImageConfig = issuer.imageConfig();
        issuerContainer = issuer.container();
        issuerManager = issuer.manager();
        issuanceService = issuer.issuanceService();
        currentStatusList = issuer.statusList();
        jwtKey = issuer.jwtKey();
        unauthenticatedJwtKey = issuer.unauthenticatedJwtKey();
        keyId = issuer.keyId();
        issuerManagementAccessToken = issuer.managementAccessToken();
        managementAuthConfig = issuer.managementAuthConfig();
        mockServerClientConfig.setCurrentStatusList(
                issuerConfig.getIssuerDid(),
                String.valueOf(currentStatusList.getStatusRegistryUrl())
        );
        if (wallet != null) {
            wallet.useIssuer(issuer);
        }
    }

    protected void useVerifier(final VerifierHandle verifier) {
        currentVerifier = verifier;
        verifierConfig = verifier.config();
        verifierImageConfig = verifier.imageConfig();
        verifierContainer = verifier.container();
        verifierManager = verifier.manager();
        verifierManagementAccessToken = verifier.managementAccessToken();
        if (verifier.managementAuthConfig().isEnabled()
                || currentIssuer == null
                || !currentIssuer.managementAuthConfig().isEnabled()) {
            managementAuthConfig = verifier.managementAuthConfig();
        }
        if (wallet != null) {
            wallet.useVerifier(verifier);
        }
    }

    protected void useComponents(final IssuerHandle issuer, final VerifierHandle verifier) {
        useIssuer(issuer);
        useVerifier(verifier);
    }

    @BeforeEach
    void setupMockServerVerificationClient() {
        mockServerClient = new MockServerClient(
                mockServerContainer.getHost(),
                mockServerContainer.getServerPort()
        );
    }

    @BeforeEach
    void setupTrace(TestInfo testInfo) throws Exception {
        if (!applicationTestConfig.isTrace()) {
            return;
        }

        final String className = testInfo.getTestClass()
                .map(Class::getSimpleName)
                .orElse("UnknownClass");

        final String methodName = testInfo.getTestMethod()
                .map(Method::getName)
                .orElse("unknownMethod");

        final String displayName = testInfo.getDisplayName();
        final boolean isParameterized = displayName.matches(".*\\[(\\d+)\\].*");

        int invocationId = 0;

        if (isParameterized) {
            final String key = className + "#" + methodName;
            final AtomicInteger counter = invocationCounters.computeIfAbsent(key, k -> new AtomicInteger(0));
            invocationId = counter.incrementAndGet();
        }

        final String name = isParameterized
                ? "%s/%s_%d".formatted(className, methodName, invocationId)
                : "%s/%s".formatted(className, methodName);

        final File traceFile = new File("target/request-traces/" + name + ".md");
        traceFile.getParentFile().mkdirs();
        Files.deleteIfExists(traceFile.toPath());
        Files.createFile(traceFile.toPath());

        log.info("HTTP tracing enabled → {}", traceFile.getAbsolutePath());

        RestClient.Builder builder = RestClient.builder();

        builder = builder.requestFactory(
                        new BufferingClientHttpRequestFactory(new SimpleClientHttpRequestFactory()))
                .requestInterceptor(new HttpTraceInterceptor(traceFile, "Wallet"));

        restClient = builder.build();

        final ServiceLocationContext issuerContext = wallet.getIssuerContext();
        final ServiceLocationContext verifierContext = wallet.getVerifierContext();
        final boolean useEncryption = wallet.isUseEncryption();
        final boolean useDPoP = wallet.isUseDPoP();
        final boolean signedMetadataPreferred = wallet.isSignedMetadataPreferred();
        final String credentialRequestEncryptionEnc = wallet.getCredentialRequestEncryptionEnc();
        final String credentialResponseEncryptionEnc = wallet.getCredentialResponseEncryptionEnc();
        final MockAttestationAuthority activeMockAttestationAuthority = wallet.getMockAttestationAuthority();

        wallet = new Wallet(restClient, issuerContext, verifierContext);
        wallet.setUseEncryption(useEncryption);
        wallet.setUseDPoP(useDPoP);
        wallet.setSignedMetadataPreferred(signedMetadataPreferred);
        wallet.setCredentialRequestEncryptionEnc(credentialRequestEncryptionEnc);
        wallet.setCredentialResponseEncryptionEnc(credentialResponseEncryptionEnc);
        wallet.setMockAttestationAuthority(activeMockAttestationAuthority);

        issuerManager.intercept(new HttpTraceInterceptor(traceFile, "Issuer Management"));
        verifierManager.intercept(new HttpTraceInterceptor(traceFile, "Verifier Management"));
    }

    @AfterAll
    void tearDown() throws Exception {
        if (connection != null && !connection.isClosed()) {
            connection.close();
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, String> errorJson(HttpClientErrorException ex) {
        return (Map<String, String>) ex.getResponseBodyAs(Map.class);
    }

    @SuppressWarnings("unchecked")
    public static int errorCode(HttpClientErrorException ex) {
        return ex.getStatusCode().value();
    }

    protected void blockTable(String tableName) {
        try {
            stmt.execute("ALTER TABLE " + tableName +
                    " ADD CONSTRAINT test_block_table CHECK (false) NOT VALID");
        } catch (SQLException e) {
            throw new RuntimeException(String.format("The blocking of the table %s failed.", tableName), e);
        }
    }

    protected void unblockTable(String tableName) {
        try {
            stmt.execute("ALTER TABLE " + tableName +
                    " DROP CONSTRAINT IF EXISTS test_block_table");
        } catch (SQLException e) {
            throw new RuntimeException(String.format("The unblocking of the table %s failed.", tableName), e);
        }
    }
}
