package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.WebhookCallback;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.UseWallet;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/** Exercises EIDOMNI-1229 through the real scheduler and Hibernate, without management reads expiring the offers. */
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.OFFER_EXPIRATION)
@UseWallet(dpop = true, encryption = true, signedMetadata = true)
class IssuerOfferExpirationSchedulerTest extends BaseTest {

    private static final Duration EXPIRATION_TIMEOUT = Duration.ofSeconds(15);
    private static final Duration REPEATED_TICKS = Duration.ofSeconds(3);

    @ParameterizedTest(name = "incompatible persisted credential_request: {0}")
    @ValueSource(strings = {"[\"not-a-credential-request\"]", "{\"proof\":\"not-an-object\"}"})
    @XrayTest(key = "EIDOMNI-1564",
            summary = "Credential Issuer expires healthy offers despite an unreadable persisted Credential Request",
            description = """
                    Given offered and deferred offers, an issued credential and a future offer in the Issuer database.
                    When one deferred offer's persisted credential_request is replaced with incompatible JSON
                    and the real expiration scheduler processes the expired offers across successive runs.
                    Then healthy offers expire, their stored personal data is cleared
                    and their EXPIRED callbacks arrive.
                    The unreadable offer is reported and remains unchanged; issued and future offers remain unchanged.
                    Later scheduler ticks do not emit additional expiration callbacks for already expired offers.
                    Spec: EIDOMNI-1229 product regression (scheduler isolation and recovery).
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCI_C1B_STORE_THE_CREDENTIAL_OFFER_IN_THE_DATABASE)
    @Tag(ReportingTags.UCI_I1D_CREATE_WEBHOOK_STATUS_CHANGE)
    void issuerScheduler_whenPersistedCredentialRequestIsUnreadable_thenOtherOffersExpireAcrossRuns(
            final String incompatibleRequest) throws SQLException {
        // Given: a real deferred flow persists a Credential Request before the database fault is injected.
        final var broken = issuerManager.createDeferredCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final var deferredEntry = wallet.collectTransactionIdFromDeferredOffer(toUri(broken.getOfferDeeplink()));
        assertThat(deferredEntry.getTransactionId())
                .isNotNull();
        final PersistedOffer originalBroken = readOffer(broken);
        assertThat(originalBroken.status())
                .isEqualTo("DEFERRED");
        assertThat(originalBroken.credentialRequest())
                .isNotBlank();

        final var offered = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final var deferred = issuerManager.createDeferredCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        wallet.collectTransactionIdFromDeferredOffer(toUri(deferred.getOfferDeeplink()));
        final var future = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final PersistedOffer originalFuture = readOffer(future);
        final var issued = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        wallet.collectOffer(toUri(issued.getOfferDeeplink()));
        assertThat(readOffer(issued).status())
                .isEqualTo("ISSUED");
        final List<CredentialWithDeeplinkResponse> firstRun = List.of(broken, offered, deferred, issued);
        final String schema = currentIssuer.imageConfig().getDbSchema();

        try {
            // When: commit the corrupt JSON and expired deadlines atomically, before a scheduler tick can see them.
            // The JSON is syntactically valid for PostgreSQL but cannot be mapped to CredentialRequestClass.
            try (var update = connection.prepareStatement("UPDATE " + schema + ".credential_offer"
                    + " SET offer_expiration_timestamp = ?, credential_request = CASE WHEN id = ?"
                    + " THEN CAST(? AS jsonb) ELSE credential_request END"
                    + " WHERE id IN (?, ?, ?, ?)")) {
                update.setLong(1, Instant.now().minusSeconds(60).getEpochSecond());
                update.setObject(2, broken.getOfferId());
                update.setString(3, incompatibleRequest);
                for (int index = 0; index < firstRun.size(); index++) {
                    update.setObject(index + 4, firstRun.get(index).getOfferId());
                }
                assertThat(update.executeUpdate())
                        .isEqualTo(firstRun.size());
            }
            final PersistedOffer corruptBroken = readOffer(broken);
            final PersistedOffer terminalIssued = readOffer(issued);

            // Then: SQL reads do not trigger the management API's separate on-access expiration logic.
            await().atMost(EXPIRATION_TIMEOUT).untilAsserted(() -> {
                for (var healthy : List.of(offered, deferred)) {
                    final PersistedOffer expired = readOffer(healthy);
                    assertThat(expired.status())
                            .as("Scheduler expires healthy offer %s despite the corrupt record", healthy.getOfferId())
                            .isEqualTo("EXPIRED");
                    assertThat(expired.offerData())
                            .isNull();
                    assertThat(expired.credentialRequest())
                            .isNull();
                }
            });
            assertThat(issuerContainer.getLogs())
                    .contains("Could not expire offer " + broken.getOfferId())
                    .contains("Could not deserialize string to java type")
                    .contains("CredentialRequestClass");
            assertThat(readOffer(broken))
                    .isEqualTo(corruptBroken);

            // When: a later run receives another eligible offer while the same broken row is still present.
            final var next = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
            try (var update = connection.prepareStatement("UPDATE " + schema
                    + ".credential_offer SET offer_expiration_timestamp = ?"
                    + " WHERE id = ? AND credential_management_id = ?")) {
                update.setLong(1, Instant.now().minusSeconds(60).getEpochSecond());
                update.setObject(2, next.getOfferId());
                update.setObject(3, next.getManagementId());
                assertThat(update.executeUpdate())
                        .isEqualTo(1);
            }
            final var observedIds = List.of(broken.getOfferId(), offered.getOfferId(), deferred.getOfferId(),
                    issued.getOfferId(), future.getOfferId(), next.getOfferId());

            // Then: expiration callbacks concern only the healthy offers, never the corrupt, issued or future offer.
            await().atMost(EXPIRATION_TIMEOUT).untilAsserted(() -> assertThat(issuerCallbacks().stream()
                    .filter(callback -> observedIds.contains(callback.getSubjectId()))
                    .filter(callback -> callback.getEventType() == WebhookCallback.EventTypeEnum.VC_STATUS_CHANGED)
                    .filter(callback -> "EXPIRED".equals(callback.getEvent()))
                    .map(WebhookCallback::getSubjectId)
                    .toList())
                    .containsOnly(offered.getOfferId(), deferred.getOfferId(), next.getOfferId()));
            awaitStableIssuerCallbacks();
            // The issuer currently publishes EXPIRED twice per transition (state machine and state service).
            // Cardinality is a separate product issue; preserve the observed callbacks across subsequent ticks.
            final var callbacksAfterExpiration = issuerCallbacks().stream()
                    .filter(callback -> observedIds.contains(callback.getSubjectId()))
                    .toList();

            // Later ticks must neither mutate terminal states nor produce additional callbacks for these offers.
            await().during(REPEATED_TICKS).atMost(EXPIRATION_TIMEOUT).untilAsserted(() -> {
                final PersistedOffer expiredNext = readOffer(next);
                assertThat(expiredNext.status())
                        .isEqualTo("EXPIRED");
                assertThat(expiredNext.offerData())
                        .isNull();
                assertThat(readOffer(broken))
                        .isEqualTo(corruptBroken);
                assertThat(readOffer(issued))
                        .isEqualTo(terminalIssued);
                assertThat(readOffer(future))
                        .isEqualTo(originalFuture);
                assertThat(issuerCallbacks().stream()
                        .filter(callback -> observedIds.contains(callback.getSubjectId()))
                        .toList())
                        .containsExactlyElementsOf(callbacksAfterExpiration);
            });
        } finally {
            // Restore this offer even on regression, so no corrupt record can poison later tests or scheduler ticks.
            try (var restore = connection.prepareStatement("UPDATE " + schema
                    + ".credential_offer SET credential_request = CAST(? AS jsonb), offer_expiration_timestamp = ?"
                    + " WHERE id = ? AND credential_management_id = ?")) {
                restore.setString(1, originalBroken.credentialRequest());
                restore.setLong(2, originalBroken.expirationTimestamp());
                restore.setObject(3, broken.getOfferId());
                restore.setObject(4, broken.getManagementId());
                restore.executeUpdate();
            }
        }
    }

    private PersistedOffer readOffer(final CredentialWithDeeplinkResponse offer) throws SQLException {
        try (var query = connection.prepareStatement("SELECT credential_status, credential_request::text,"
                + " offer_data::text, offer_expiration_timestamp FROM " + currentIssuer.imageConfig().getDbSchema()
                + ".credential_offer WHERE id = ? AND credential_management_id = ?")) {
            query.setObject(1, offer.getOfferId());
            query.setObject(2, offer.getManagementId());
            try (var rows = query.executeQuery()) {
                if (!rows.next()) {
                    throw new IllegalStateException("Missing test offer " + offer.getOfferId());
                }
                return new PersistedOffer(rows.getString(1), rows.getString(2), rows.getString(3), rows.getLong(4));
            }
        }
    }

    private record PersistedOffer(String status, String credentialRequest, String offerData, long expirationTimestamp) {
    }
}
