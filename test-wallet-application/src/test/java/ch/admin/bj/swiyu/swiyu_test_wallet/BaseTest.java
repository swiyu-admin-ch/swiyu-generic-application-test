package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ApplicationTestConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuanceService;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.HttpTraceInterceptor;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.io.File;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
        properties = {
                "server.port=${systemtests.port:18888}",
                "server.address=0.0.0.0"
        },
        classes = SwiyuTestWalletApplication.class
)
@ActiveProfiles("systemtests")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@Slf4j
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
    protected MockServerContainer mockServer;

    protected Connection connection;
    protected Wallet wallet;
    protected StatusList currentStatusList;
    protected BusinessIssuer issuerManager;
    protected IssuanceService issuanceService;
    protected VerifierManager verifierManager;
    protected RestClient restClient;
    protected Statement stmt;
    private File traceFile;
    private final Map<String, AtomicInteger> invocationCounters = new HashMap<>();

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

        final ServiceLocationContext issuerContext = new ServiceLocationContext(
                issuerContainer.getHost(), issuerContainer.getMappedPort(8080).toString()
        );

        final ServiceLocationContext verifierContext = new ServiceLocationContext(
                verifierContainer.getHost(), verifierContainer.getMappedPort(8080).toString()
        );

        currentStatusList = issuerManager.createStatusList(100000, 2);

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
    static Map<String, String> errorJson(HttpClientErrorException ex) {
        return (Map<String, String>) ex.getResponseBodyAs(Map.class);
    }

    @SuppressWarnings("unchecked")
    static int errorCode(HttpClientErrorException ex) {
        return ex.getStatusCode().value();
    }
}
