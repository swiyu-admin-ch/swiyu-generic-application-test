package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.webhook_callback;

import ch.admin.bj.swiyu.gen.issuer.model.WebhookCallback;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.testcontainers.shaded.org.awaitility.Awaitility;

import java.time.Duration;
import java.util.List;
import java.util.function.Predicate;

@Slf4j
public final class WebhookCallbackAssert {

    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration POLL_INTERVAL = Duration.ofMillis(200);

    private final List<WebhookCallback> callbacks;

    private WebhookCallbackAssert(final List<WebhookCallback> callbacks) {
        this.callbacks = callbacks;
    }

    public static WebhookCallbackAssert assertThat(final List<WebhookCallback> callbacks) {
        Assertions.assertThat(callbacks)
                .as("Callback list must not be null")
                .isNotNull();

        return new WebhookCallbackAssert(callbacks);
    }

    public WebhookCallbackAssert hasSizeEventually(final int expectedSize) {
        try {
            Awaitility.await()
                    .pollInterval(POLL_INTERVAL)
                    .atMost(DEFAULT_TIMEOUT)
                    .until(() -> {
                        int currentSize = callbacks.size();
                        return currentSize == expectedSize;
                    });

        } catch (Exception e) {
            final int currentSize = callbacks.size();
            callbacks.forEach(cb -> log.error(" -> {}", cb));
            throw new AssertionError(
                    "Expected callback size to be %d but was %d"
                            .formatted(expectedSize, currentSize),
                    e
            );
        }

        return this;
    }

    public WebhookCallbackAssert isEmptyEventually() {
        Awaitility.await()
                .pollInterval(POLL_INTERVAL)
                .atMost(DEFAULT_TIMEOUT)
                .until(callbacks::isEmpty);

        Assertions.assertThat(callbacks).isEmpty();
        return this;
    }

    public WebhookCallbackAssert hasLastCallbacksInOrder(List<WebhookCallback> expected) {
        final int actualSize = callbacks.size();
        final int expectedSize = expected.size();
        Assertions.assertThat(actualSize)
                .as("Actual callback list size (%s) must be >= expected size (%s)",
                        actualSize, expectedSize)
                .isGreaterThanOrEqualTo(expectedSize);

        final int offset = actualSize - expectedSize;
        for (int i = 0; i < expectedSize; i++) {
            final WebhookCallback actualCb = callbacks.get(offset + i);
            final WebhookCallback expectedCb = expected.get(i);
            Assertions.assertThat(actualCb)
                    .as("Callback mismatch at relative index %s (actual index %s)", i, offset + i)
                    .usingRecursiveComparison()
                    .ignoringFields("timestamp")
                    .isEqualTo(expectedCb);
        }

        return this;
    }
}