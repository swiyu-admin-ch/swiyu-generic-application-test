package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.DBContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.junit.jupiter.api.*;
import org.assertj.core.api.AssertionsForClassTypes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.sql.*;


import java.util.List;

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
    @Tag("issuer")
    void batchIssuanceFlow_thenSuccess() throws SQLException {
        final int batchSize = 3;

        final StatusList currentStatusList = issuerManager.createStatusList(batchSize, 2);

        wallet.setEncryptionPreferred(true);

        ResultSet rsBefore = stmt.executeQuery(""" 
                SELECT next_free_index
                FROM %s.status_list
                WHERE id = '%s'
        """.formatted(DBContainerConfig.ISSUER_DB_SCHEMA, currentStatusList.getId()));
        rsBefore.next();
        final int initialNextFreeIndex = rsBefore.getInt("next_free_index");

        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("university_example_sd_jwt");

        final WalletBatchEntry batchEntry = wallet.collectOfferBatch(toUri(response.getOfferDeeplink()), batchSize);

        assertThat(batchEntry.getIssuedCredentials().size()).isEqualTo(batchSize);

        final ResultSet rsAfter = stmt.executeQuery(""" 
                SELECT next_free_index
                FROM %s.status_list
                WHERE id = '%s'
        """.formatted(DBContainerConfig.ISSUER_DB_SCHEMA, currentStatusList.getId()));
        rsAfter.next();
        final int updatedNextFreeIndex = rsAfter.getInt("next_free_index");

        int deltaFreeIndex = updatedNextFreeIndex - initialNextFreeIndex;

        assertThat(deltaFreeIndex)
                .as("next_free_index should not increase by 1 only during a batch")
                .isNotEqualTo(1);

        assertThat(deltaFreeIndex)
                .as("next_free_index should not increase sequentially")
                .isEqualTo(batchSize);
    }

    @Test
    @Tag("issuer")
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
                .contains(String.format("\"detail\":\"Max length %d exceeded for status list", statusListLength));
    }

}
