package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import org.junit.jupiter.api.*;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.HttpRequest;
import org.mockserver.verify.VerificationTimes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class RandomizedIndexTest {

    @Autowired
    IssuerImageConfig issuerImageConfig;
    @Autowired
    VerifierImageConfig verifierImageConfig;
    @Autowired
    IssuerConfig issuerConfig;
    @Autowired
    GenericContainer<?> issuerContainer;
    @Autowired
    GenericContainer<?> verifierContainer;
    @Autowired
    PostgreSQLContainer<?> dbTestContainer;
    @Autowired
    MockServerContainer mockServer;

    private Wallet wallet;
    private BusinessIssuer issuerManager;
    private VerifierManager verifierManager;
    private Connection connection;
    private Statement stmt;
    private MockServerClient mockClient;

    @BeforeAll
    void setup() throws Exception {
        issuerConfig.setIssuerServiceUrl(toUri("http://%s:%s".formatted(issuerContainer.getHost(), issuerContainer.getMappedPort(8080))).toString());
        issuerManager = new BusinessIssuer(issuerConfig);
        verifierManager = new VerifierManager(toUri("http://%s:%s".formatted(verifierContainer.getHost(), verifierContainer.getMappedPort(8080))).toString());
        RestClient restClient = RestClient.builder().build();
        ServiceLocationContext issuerContext = new ServiceLocationContext(issuerContainer.getHost(), issuerContainer.getMappedPort(8080).toString());
        ServiceLocationContext verifierContext = new ServiceLocationContext(verifierContainer.getHost(), verifierContainer.getMappedPort(8080).toString());

        wallet = new Wallet(restClient, issuerContext, verifierContext);

        String jdbcUrl = dbTestContainer.getJdbcUrl();
        String username = dbTestContainer.getUsername();
        String password = dbTestContainer.getPassword();

        connection = DriverManager.getConnection(jdbcUrl, username, password);
        stmt = connection.createStatement();

        //mockClient = new MockServerClient(mockServer.getHost(), mockServer.getServerPort());
    }

    @AfterAll
    void tearDown() throws Exception {
        if (connection != null && !connection.isClosed()) connection.close();
        //if (mockClient != null) mockClient.close();
    }

    @BeforeEach
    void beforeEach() throws SQLException {
        wallet.setEncryptionPreferred(false);
        stmt.execute("TRUNCATE TABLE swiyu_issuer.status_list RESTART IDENTITY CASCADE");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-410",
            summary = "Batch issuance with randomized status list index allocation",
            description = """
                    This test validates that status list index allocation behaves as expected during mixed single and batch SD-JWT 
                    credential issuance. The test ensures that indexes used for status entries are not sequential even when combining 
                    individual and batch credential creation through the OID4VCI issuance flow.
                    
                    Steps:
                    1. The issuer creates a status list with a defined maximum length and configuration.
                    2. The issuer issues one SD-JWT credential and stores its index in the status list.
                    3. The wallet collects the single credential offer.
                    4. The issuer performs a batch issuance of SD-JWT credentials (multiple credentials per offer).
                    5. The wallet collects all batch credentials.
                    6. The database is queried for all used indexes.
                    7. The test asserts that the number of credentials matches the expected count and that indexes are not sequential.
                    """
    )
    //@ComponentTest("issuer")
    @Tag("issuance")
    void fullBatchFlow_withRandomIndexes() throws Exception {
        final int statusListLength = 10000;
        issuerManager.createStatusList(statusListLength, 2);

        final CredentialWithDeeplinkResponse singleResponse =
                issuerManager.createCredentialOffer("university_example_sd_jwt");
        wallet.collectOffer(toUri(singleResponse.getOfferDeeplink()));

        final int afterSingle = getUsedIndexesFromDb().size();
        assertThat(afterSingle)
                .as("Expected one entry after single credential issuance")
                .isEqualTo(1);
        final CredentialWithDeeplinkResponse batchResponse =
                issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        wallet.collectOfferBatch(toUri(batchResponse.getOfferDeeplink()), 3);

        final List<Integer> allIndexes = getUsedIndexesFromDb();

        assertThat(allIndexes.size())
                .as("Expected total of 4 credentials (1 single + 3 in batch)")
                .isEqualTo(4);

        assertThat(areSequential(allIndexes))
                .as("Indexes must not be sequential even for a single + batch issuance")
                .isFalse();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-408",
            summary = "Concurrent batch issuance over a large status list",
            description = """
                    This test validates the behavior of concurrent SD-JWT credential batch issuance when operating over a large 
                    status list. It ensures that multiple parallel issuance operations correctly allocate unique indexes without 
                    collisions or sequential patterns.
                    
                    Steps:
                    1. The issuer creates a large status list configured for token status entries.
                    2. Multiple concurrent threads are launched, each performing a batch issuance of SD-JWT credentials.
                    3. Each batch offer is collected by the wallet.
                    4. After all threads complete, the database is queried for all used indexes.
                    5. The test asserts that the total number of issued credentials matches the expected total and that indexes are 
                       non-sequential across batches.
                    """
    )
    //@ComponentTest("issuer")
    @Tag("batch-issuance")
    void multipleConcurrentBatches_largeStatusList() throws Exception {
        final int statusListLength = 10000;
        final int batchCount = 10;
        final int batchSize = 3;

        issuerManager.createStatusList(statusListLength, 2);

        ExecutorService pool = Executors.newFixedThreadPool(batchCount);
        Callable<Void> batchJob = () -> {
            CredentialWithDeeplinkResponse response =
                    issuerManager.createCredentialOffer("unbound_example_sd_jwt");
            wallet.collectOfferBatch(toUri(response.getOfferDeeplink()), batchSize);
            return null;
        };

        List<Callable<Void>> jobs = new ArrayList<>();
        for (int i = 0; i < batchCount; i++) {
            jobs.add(batchJob);
        }

        pool.invokeAll(jobs);
        pool.shutdown();
        pool.awaitTermination(60, TimeUnit.SECONDS);

        List<Integer> allIndexes = getUsedIndexesFromDb();

        assertThat(allIndexes.size())
                .as("Expected %s total credentials (%s batches × %s each)", batchCount * batchSize, batchCount, batchSize)
                .isEqualTo(batchCount * batchSize);

        assertThat(areSequential(allIndexes))
                .as("Indexes across all batches must not be sequential when issued concurrently")
                .isFalse();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-411",
            summary = "Concurrent batch issuance with to small status list capacity",
            description = """
                    This test validates the issuer's behavior when handling concurrent batch SD-JWT issuance requests under 
                    constrained status list capacity. It verifies that issuance succeeds up to available index capacity and that 
                    excess requests are properly constrained by configuration.
                    
                    Steps:
                    1. The issuer creates a small status list with limited capacity.
                    2. Multiple concurrent threads are launched, each initiating a batch issuance request for SD-JWT credentials.
                    3. Each batch offer is collected by the wallet.
                    4. The system waits for all batch operations to complete.
                    5. The database is queried to verify that the number of issued credentials matches the expected limit.
                    6. The test ensures that issuance stops once the list capacity is reached.
                    """
    )
    //@ComponentTest("issuer")
    @Tag("batch-issuance")
    void multipleConcurrentBatches_smallStatusList() throws Exception {
        final int statusListLength = 20;
        final int batchCount = 10;
        final int batchSize = 3;

        issuerManager.createStatusList(statusListLength, 2);

        ExecutorService pool = Executors.newFixedThreadPool(batchCount);
        Callable<Void> batchJob = () -> {
            CredentialWithDeeplinkResponse response =
                    issuerManager.createCredentialOffer("unbound_example_sd_jwt");
            wallet.collectOfferBatch(toUri(response.getOfferDeeplink()), batchSize);
            return null;
        };

        List<Callable<Void>> jobs = new ArrayList<>();
        for (int i = 0; i < batchCount; i++) {
            jobs.add(batchJob);
        }

        pool.invokeAll(jobs);
        pool.shutdown();
        pool.awaitTermination(60, TimeUnit.SECONDS);

        List<Integer> allIndexes = getUsedIndexesFromDb();

        assertThat(allIndexes.size())
                .as("Expected %s total credentials (%s batches × %s each)", 18, batchCount, batchSize)
                .isEqualTo(18);
    }

    private List<Integer> getUsedIndexesFromDb() throws SQLException {
        List<Integer> indexes = new ArrayList<>();
        String query = """
                SELECT index
                FROM swiyu_issuer.credential_offer_status
                ORDER BY index ASC
                """;
        try (ResultSet rs = stmt.executeQuery(query)) {
            while (rs.next()) indexes.add(rs.getInt("index"));
        }
        return indexes;
    }

    private boolean areSequential(List<Integer> indexes) {
        if (indexes.size() < 2) return false;
        List<Integer> sorted = indexes.stream().sorted().collect(Collectors.toList());
        for (int i = 1; i < sorted.size(); i++) {
            if (sorted.get(i) - sorted.get(i - 1) != 1) return false;
        }
        return true;
    }

    private void assertCallbackWasCalled(MockServerClient mockClient, String path) {
        mockClient.verify(
                HttpRequest.request()
                        .withMethod("POST")
                        .withPath(path),
                VerificationTimes.atLeast(1)
        );
    }
}
