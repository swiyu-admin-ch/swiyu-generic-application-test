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
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.Assert.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class BatchTest {

    @Autowired
    IssuerImageConfig issuerImageConfig;
    @Autowired
    VerifierImageConfig verifierImageConfig;
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
    }

    @AfterAll
    void tearDown() throws Exception {
        if (connection != null && !connection.isClosed()) {
            connection.close();
        }
    }

    @BeforeEach
    void beforeEach() {
        wallet.setEncryptionPreferred(false);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-388",
            summary = "Successful SD-JWT batch issuance flow",
            description = """
                    This test validates that the issuer successfully performs a batch issuance of multiple SD-JWT credentials 
                    in a single offer, ensuring that all issued credentials receive non-sequential status list indexes. 
                    The flow follows the OID4VCI issuance process with encryption enabled.
                    
                    Steps:
                    1. The issuer initializes a status list with a defined capacity and bit configuration.
                    2. The wallet indicates encryption preference for credential issuance responses.
                    3. The issuer creates a credential offer for an unbound SD-JWT credential.
                    4. The wallet collects the offer in batch mode and retrieves multiple SD-JWT credentials.
                    5. The system queries the status list to extract all used indexes.
                    6. The test verifies that the number of issued credentials matches the requested batch size and that 
                       indexes are not strictly sequential across the batch.
                    """
    )
    //@ComponentTest("issuer")
    @Tag("batch-issuance")
    void batchIssuanceFlow_thenSuccess() throws SQLException {
        final int batchSize = 3;

        issuerManager.createStatusList(10000, 2);

        wallet.setEncryptionPreferred(true);

        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");

        final WalletBatchEntry batchEntry = wallet.collectOfferBatch(toUri(response.getOfferDeeplink()), batchSize);

        assertThat(batchEntry.getIssuedCredentials().size()).isEqualTo(batchSize);

        List<Integer> indexes = getUsedIndexesFromDb();

        assertThat(areSequential(indexes))
                .as("Indexes in status_list should not be strictly sequential")
                .isFalse();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-395",
            summary = "Batch issuance rejected when status list capacity exceeded",
            description = """
                    This test ensures that the issuer correctly rejects a batch SD-JWT issuance request when the 
                    number of credentials to be issued exceeds the remaining capacity of the configured status list.
                    
                    Steps:
                    1. The issuer creates a status list with limited capacity (e.g., length 2).
                    2. The wallet enables encryption preference for issuance.
                    3. The issuer attempts to create a credential offer for an SD-JWT credential.
                    4. The wallet requests to collect multiple credentials in a batch exceeding the status list capacity.
                    5. The issuer responds with an HTTP 400 Bad Request.
                    6. The test validates that the error message indicates insufficient available status indexes.
                    """
    )
    //@ComponentTest("issuer")
    @Tag("batch-issuance")
    void batchIssuanceFlowExceedStatusList_thenReject() throws SQLException {
        final int batchSize = 3;
        final int statusListLength = 2;

        issuerManager.createStatusList(statusListLength, 2);

        wallet.setEncryptionPreferred(true);

        HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
            final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("university_example_sd_jwt");

            wallet.collectOfferBatch(toUri(response.getOfferDeeplink()), batchSize);
        });

        assertThat(ex.getStatusCode().value())
                .as("Expected HTTP 400 Bad Request")
                .isEqualTo(400);

        assertThat(ex.getMessage())
                .as("Expected message to contain Bad Request and detail about max length exceeded")
                .contains("\"detail\":\"Too few status indexes remain in status list");
    }

    private boolean areSequential(final List<Integer> indexes) {
        if (indexes.size() < 2) return false;

        final List<Integer> sorted = indexes.stream().sorted().collect(Collectors.toList());
        for (int i = 1; i < sorted.size(); i++) {
            if (sorted.get(i) - sorted.get(i - 1) != 1) return false;
        }

        return true;
    }

    private List<Integer> getUsedIndexesFromDb() throws SQLException {
        final List<Integer> indexes = new ArrayList<>();

        final String query = """
                    SELECT index
                    FROM swiyu_issuer.credential_offer_status
                    ORDER BY index ASC
                """;

        try (ResultSet rs = stmt.executeQuery(query)) {
            while (rs.next()) {
                indexes.add(rs.getInt("index"));
            }
        }

        return indexes;
    }

}
