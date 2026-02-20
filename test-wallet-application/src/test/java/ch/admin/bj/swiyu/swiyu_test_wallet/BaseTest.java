package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ApplicationTestConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
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
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntSupplier;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig.ISSUER_CALLBACK_PATH;
import static ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig.VERIFIER_CALLBACK_PATH;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
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
    protected IssuerConfig issuerConfig;
    @Autowired
    protected GenericContainer<?> issuerContainer;
    @Autowired
    protected GenericContainer<?> verifierContainer;
    @Autowired
    protected PostgreSQLContainer<?> dbTestContainer;
    @Autowired
    protected MockServerContainer mockServerContainer;
    @Autowired
    protected MockServerClientConfig mockServerClientConfig;
    protected MockServerClient mockServerClient;

    protected Connection connection;
    protected Wallet wallet;
    @Getter private StatusList currentStatusList;
    protected BusinessIssuer issuerManager;
    protected IssuanceService issuanceService;
    protected VerifierManager verifierManager;
    protected RestClient restClient;
    protected Statement stmt;
    protected PrivateKey jwtKey;
    protected PrivateKey unauthenticatedJwtKey;
    private File traceFile;
    private final Map<String, AtomicInteger> invocationCounters = new HashMap<>();

    protected void setCurrentStatusList(StatusList currentStatusList) {
        if (currentStatusList == null) {
            throw new IllegalArgumentException("currentStatusList cannot be null");
        }
        this.currentStatusList = currentStatusList;
        mockServerClientConfig.setCurrentStatusList(String.valueOf(currentStatusList.getStatusRegistryUrl()));
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

    protected int awaitStableCount(final IntSupplier counter) {
        final AtomicInteger previous = new AtomicInteger(-1);

        await()
                .pollInterval(Duration.ofMillis(200))
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
        issuerConfig.setIssuerServiceUrl(
                toUri("http://%s:%s".formatted(
                        issuerContainer.getHost(), issuerContainer.getMappedPort(8080)
                )).toString()
        );

        issuerManager = new BusinessIssuer(issuerConfig);
        issuanceService = new IssuanceService(toUri("http://%s:%s".formatted(issuerContainer.getHost(), issuerContainer.getMappedPort(8080))).toString());
        verifierManager = new VerifierManager(
                toUri("http://%s:%s".formatted(
                        verifierContainer.getHost(), verifierContainer.getMappedPort(8080)
                )).toString()
        );

        if (issuerImageConfig.isEnableJwtAuth() && issuerImageConfig.getJwtKeyGenerator() != null) {
            jwtKey = issuerImageConfig.getJwtKeyGenerator().getPrivateKey();

            final KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
            final ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
            keyPairGen.initialize(ecSpec);
            unauthenticatedJwtKey = keyPairGen.generateKeyPair().getPrivate();
        }

        final ServiceLocationContext issuerContext = new ServiceLocationContext(
                issuerContainer.getHost(), issuerContainer.getMappedPort(8080).toString()
        );

        final ServiceLocationContext verifierContext = new ServiceLocationContext(
                verifierContainer.getHost(), verifierContainer.getMappedPort(8080).toString()
        );

        if (issuerImageConfig.isEnableJwtAuth()) {
            setCurrentStatusList(issuerManager.createStatusListWithSignedJwt(jwtKey, "test-key-1", 100000, 2));
        } else {
            setCurrentStatusList(issuerManager.createStatusList(100000, 2));
        }
        connection = DriverManager.getConnection(
                dbTestContainer.getJdbcUrl(),
                dbTestContainer.getUsername(),
                dbTestContainer.getPassword()
        );
        stmt = connection.createStatement();

        restClient = RestClient.builder().build();

        wallet = new Wallet(restClient, issuerContext, verifierContext);
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

        final ServiceLocationContext issuerContext = new ServiceLocationContext(
                issuerContainer.getHost(), issuerContainer.getMappedPort(8080).toString()
        );

        final ServiceLocationContext verifierContext = new ServiceLocationContext(
                verifierContainer.getHost(), verifierContainer.getMappedPort(8080).toString()
        );

        wallet = new Wallet(restClient, issuerContext, verifierContext);


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
}
