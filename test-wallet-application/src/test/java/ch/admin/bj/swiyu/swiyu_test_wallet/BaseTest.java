package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

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
    protected VerifierManager verifierManager;
    protected RestClient restClient;
    protected Statement stmt;

    @BeforeAll
    void setup() throws Exception {
        issuerConfig.setIssuerServiceUrl(toUri("http://%s:%s".formatted(issuerContainer.getHost(), issuerContainer.getMappedPort(8080))).toString());
        issuerManager = new BusinessIssuer(issuerConfig);
        verifierManager = new VerifierManager(toUri("http://%s:%s".formatted(verifierContainer.getHost(), verifierContainer.getMappedPort(8080))).toString());
        restClient = RestClient.builder().build();
        ServiceLocationContext issuerContext = new ServiceLocationContext(issuerContainer.getHost(), issuerContainer.getMappedPort(8080).toString());
        ServiceLocationContext verifierContext = new ServiceLocationContext(verifierContainer.getHost(), verifierContainer.getMappedPort(8080).toString());

        currentStatusList = issuerManager.createStatusList(100000, 2);

        wallet = new Wallet(restClient, issuerContext, verifierContext);

        String jdbcUrl = dbTestContainer.getJdbcUrl();
        String username = dbTestContainer.getUsername();
        String password = dbTestContainer.getPassword();

        connection = DriverManager.getConnection(jdbcUrl, username, password);
        stmt = connection.createStatement();
    }

    @AfterAll
    void tearDown() throws Exception {
        if (connection != null && !connection.isClosed()) {
            connection.close();
        }
    }
}
