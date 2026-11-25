package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JwtSupport;
import org.springframework.web.client.HttpClientErrorException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
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
class RandomizedIndexTest extends BaseTest {

    @BeforeEach
    void beforeEach() throws SQLException {
        wallet.setUseEncryption(false);
        stmt.execute("TRUNCATE TABLE %s.status_list RESTART IDENTITY CASCADE".formatted(issuerImageConfig.getDbSchema()));
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-410",
            summary = "Batch issuance with randomized status list index allocation",
            description = """
                    This test validates that status list index allocation is randomized during mixed single and batch
                    SD-JWT credential issuance, ensuring that indexes are not sequential even when combining individual
                    and batch credential creation through OID4VCI.
                    """
    )
    @Tag(ReportingTags.HAPPY_PATH)
    @Tag(ReportingTags.UCI_I1_ISSUING_VERIFIABLE_CREDENTIALS)
    @Tag(ReportingTags.UCI_I1A_CREATE_VERIFIABLE_CREDENTIALS)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC},
            reason = "This feature is not available yet (stable, rc). Fix not available yet (staging)."
    )
    void fullBatchFlow_withRandomIndexes() throws Exception {
        int expectedCount = 0;
        final int statusListLength = 10000;
        issuerManager.createStatusList(statusListLength, 2);

        final CredentialWithDeeplinkResponse singleResponse =
                issuerManager.createCredentialOffer("bound_example_sd_jwt");
        wallet.collectOffer(toUri(singleResponse.getOfferDeeplink()), 1);
        expectedCount += 1;

        final int afterSingle = getUsedIndexesFromDb().size();
        assertThat(afterSingle)
                .as("Expected one entry after single credential issuance")
                .isEqualTo(expectedCount);
        final CredentialWithDeeplinkResponse batchResponse =
                issuerManager.createCredentialOffer("bound_example_sd_jwt");
        wallet.collectOffer(toUri(batchResponse.getOfferDeeplink()));
        expectedCount += CredentialConfigurationFixtures.BATCH_SIZE;

        final List<Integer> allIndexes = getUsedIndexesFromDb();

        assertThat(allIndexes)
                .as("Expected total of two times the batch size")
                .hasSize(expectedCount);

        assertThat(areSequential(allIndexes))
                .as("Indexes must not be sequential even for a single + batch issuance")
                .isFalse();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-408",
            summary = "Concurrent batch issuance over a large status list",
            description = """
                    This test validates the behavior of concurrent SD-JWT credential batch issuance over a large status list,
                    ensuring that multiple parallel issuance operations correctly allocate unique randomized indexes without
                    collisions or sequential patterns across batches.
                    """
    )
    @Tag(ReportingTags.HAPPY_PATH)
    @Tag(ReportingTags.UCI_I1_ISSUING_VERIFIABLE_CREDENTIALS)
    @Tag(ReportingTags.UCI_I1A_CREATE_VERIFIABLE_CREDENTIALS)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void multipleConcurrentBatches_largeStatusList() throws Exception {
        final int batchSize = CredentialConfigurationFixtures.BATCH_SIZE;
        final int batchCount = 10;
        final int statusListLength = 10000;

        issuerManager.createStatusList(statusListLength, 2);

        final List<BatchResult> batches = new ArrayList<>();
        try (ExecutorService pool = Executors.newFixedThreadPool(batchCount)) {
            Callable<BatchResult> batchJob = () -> {
                CredentialWithDeeplinkResponse response =
                        issuerManager.createCredentialOffer("bound_example_sd_jwt");
                final var entry = newWallet().collectOffer(toUri(response.getOfferDeeplink()));
                return new BatchResult(response.getManagementId(), List.copyOf(entry.getIssuedCredentials()), null);
            };

            List<Callable<BatchResult>> jobs = new ArrayList<>();
            for (int i = 0; i < batchCount; i++) {
                jobs.add(batchJob);
            }

            for (var result : pool.invokeAll(jobs, 60, TimeUnit.SECONDS)) {
                batches.add(result.get());
            }
        }

        List<Integer> allIndexes = getUsedIndexesFromDb();

        assertThat(allIndexes)
                .as("Expected %s total credentials (%s batches × %s each)", batchCount * batchSize, batchCount, batchSize)
                .hasSize(batchCount * batchSize)
                .doesNotHaveDuplicates();

        for (final BatchResult batch : batches) {
            assertThat(batch.credentials())
                    .hasSize(batchSize);
            assertThat(batch.credentials().stream().map(this::statusReference).toList())
                    .as("Every returned credential must reference an index allocated to its own management entry")
                    .containsExactlyInAnyOrderElementsOf(statusReferencesFromDb(batch.managementId()));
        }
        assertThat(batches.stream().flatMap(batch -> batch.credentials().stream()).map(this::statusReference).toList())
                .doesNotHaveDuplicates();

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
                    constrained status list capacity, verifying that issuance succeeds up to available capacity and excess
                    requests are properly constrained.
                    """
    )
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCI_I1_ISSUING_VERIFIABLE_CREDENTIALS)
    @Tag(ReportingTags.UCI_I1A_CREATE_VERIFIABLE_CREDENTIALS)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void multipleConcurrentBatches_smallStatusList() throws Exception {
        final int batchSize = CredentialConfigurationFixtures.BATCH_SIZE;
        final int batchCount = 10;
        final int statusListLength = batchSize * batchCount - 1; // Set capacity just below total needed for all batches

        final int expectedBatchCountEntered = batchCount - 1;
        final int expectedEntries = expectedBatchCountEntered * batchSize;

        issuerManager.createStatusList(statusListLength, 2);

        final List<BatchResult> batches = new ArrayList<>();
        try (ExecutorService pool = Executors.newFixedThreadPool(batchCount)) {
            Callable<BatchResult> batchJob = () -> {
                final CredentialWithDeeplinkResponse response;
                try {
                    response = issuerManager.createCredentialOffer("bound_example_sd_jwt");
                } catch (HttpClientErrorException rejection) {
                    return new BatchResult(null, List.of(), rejection);
                }
                final var entry = newWallet().collectOffer(toUri(response.getOfferDeeplink()));
                return new BatchResult(response.getManagementId(), List.copyOf(entry.getIssuedCredentials()), null);
            };

            List<Callable<BatchResult>> jobs = new ArrayList<>();
            for (int i = 0; i < batchCount; i++) {
                jobs.add(batchJob);
            }

            for (var result : pool.invokeAll(jobs, 60, TimeUnit.SECONDS)) {
                batches.add(result.get());
            }
        }

        List<Integer> allIndexes = getUsedIndexesFromDb();

        assertThat(allIndexes)
                .as("Expected %s total credentials (%s batches × %s each)", expectedEntries, batchCount, batchSize)
                .hasSize(expectedEntries)
                .doesNotHaveDuplicates();
        assertThat(batches.stream().filter(batch -> batch.rejection() != null).toList())
                .singleElement()
                .satisfies(batch -> {
                    ApiErrorAssert.assertThat(batch.rejection())
                            .hasStatus(400);
                    assertThat(batch.rejection().getResponseBodyAsString())
                            .contains("Too few status indexes remain in status list");
                });
        final var issuedBatches = batches.stream().filter(batch -> batch.rejection() == null).toList();
        assertThat(issuedBatches)
                .hasSize(expectedBatchCountEntered);
        for (final BatchResult batch : issuedBatches) {
            assertThat(batch.credentials())
                    .hasSize(batchSize);
            assertThat(batch.credentials().stream().map(this::statusReference).toList())
                    .containsExactlyInAnyOrderElementsOf(statusReferencesFromDb(batch.managementId()));
        }
        assertThat(issuedBatches.stream().flatMap(batch -> batch.credentials().stream()).map(this::statusReference).toList())
                .hasSize(expectedEntries)
                .doesNotHaveDuplicates();
    }

    private StatusReference statusReference(final String credential) {
        final var reference = JwtSupport.decodePayloadToJsonNode(credential.split("~", 2)[0])
                .path("status").path("status_list");
        return new StatusReference(reference.path("uri").asString(), reference.path("idx").asInt());
    }

    private List<StatusReference> statusReferencesFromDb(final UUID managementId) throws SQLException {
        final List<StatusReference> references = new ArrayList<>();
        final String schema = issuerImageConfig.getDbSchema();
        try (var query = connection.prepareStatement("""
                SELECT sl.uri, cos.index FROM %s.credential_offer_status cos
                JOIN %s.status_list sl ON sl.id = cos.status_list_id
                JOIN %s.credential_offer co ON co.id = cos.credential_offer_id
                WHERE co.credential_management_id = ?
                """.formatted(schema, schema, schema))) {
            query.setObject(1, managementId);
            try (var result = query.executeQuery()) {
                while (result.next()) {
                    references.add(new StatusReference(result.getString(1), result.getInt(2)));
                }
            }
        }
        return references;
    }

    private record StatusReference(String uri, int index) {
    }

    private record BatchResult(UUID managementId, List<String> credentials, HttpClientErrorException rejection) {
    }

    private List<Integer> getUsedIndexesFromDb() throws SQLException {
        List<Integer> indexes = new ArrayList<>();
        String query = """
                SELECT index
                FROM %s.credential_offer_status
                ORDER BY index ASC
                """.formatted(issuerImageConfig.getDbSchema());
        try (ResultSet rs = stmt.executeQuery(query)) {
            while (rs.next()) indexes.add(rs.getInt("index"));
        }
        return indexes;
    }

    private boolean areSequential(List<Integer> indexes) {
        final int minimumSequentialCount = 2;
        final int consecutiveStep = 1;
        if (indexes.size() < minimumSequentialCount) return false;
        List<Integer> sorted = indexes.stream().sorted().collect(Collectors.toList());
        for (int i = 1; i < sorted.size(); i++) {
            if (sorted.get(i) - sorted.get(i - 1) != consecutiveStep) return false;
        }
        return true;
    }
}
