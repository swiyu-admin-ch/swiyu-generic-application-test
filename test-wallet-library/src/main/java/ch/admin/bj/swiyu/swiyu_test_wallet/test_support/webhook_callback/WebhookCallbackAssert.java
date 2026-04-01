package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.webhook_callback;

import ch.admin.bj.swiyu.gen.issuer.model.WebhookCallback;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.testcontainers.shaded.org.awaitility.Awaitility;

import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

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

        final List<WebhookCallback> sortedCallbacks = callbacks.stream()
                .sorted(Comparator.comparing(WebhookCallback::getTimestamp))
                .toList();

        return new WebhookCallbackAssert(sortedCallbacks);
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

    /**
     * Validates callbacks with support for groups that can appear in any order within the group.
     * For example: [A, B, (C, D), E, F] means A, then B, then either (C,D) or (D,C), then E, then F.
     *
     * @param expectedGroups A list where each element is either:
     *                       - A single WebhookCallback (strict order)
     *                       - A List<WebhookCallback> (flexible order within group)
     */
    public WebhookCallbackAssert hasLastCallbacksInOrder(List<?> expectedGroups) {
        final int actualSize = callbacks.size();

        int totalExpected = 0;
        for (Object group : expectedGroups) {
            if (group instanceof WebhookCallback) {
                totalExpected++;
            } else if (group instanceof List<?>) {
                totalExpected += ((List<?>) group).size();
            }
        }

        Assertions.assertThat(actualSize)
                .as("Actual callback list size (%s) must be >= expected size (%s)",
                        actualSize, totalExpected)
                .isGreaterThanOrEqualTo(totalExpected);

        final int offset = actualSize - totalExpected;
        int currentIndex = offset;

        for (Object group : expectedGroups) {
            if (group instanceof WebhookCallback) {
                final WebhookCallback actualCb = callbacks.get(currentIndex);
                final WebhookCallback expectedCb = (WebhookCallback) group;

                Assertions.assertThat(actualCb)
                        .as("Callback mismatch at index %d", currentIndex)
                        .usingRecursiveComparison()
                        .ignoringFields("timestamp")
                        .isEqualTo(expectedCb);

                currentIndex++;
            } else if (group instanceof List<?>) {
                @SuppressWarnings("unchecked")
                List<WebhookCallback> expectedCallbacks = (List<WebhookCallback>) group;
                int groupSize = expectedCallbacks.size();

                List<WebhookCallback> actualGroup = callbacks.subList(currentIndex, currentIndex + groupSize);
                for (WebhookCallback expected : expectedCallbacks) {
                    boolean found = actualGroup.stream()
                            .anyMatch(actual -> compareCallbacks(actual, expected));

                    Assertions.assertThat(found)
                            .as("Expected callback not found in group at index %d: %s", currentIndex, expected)
                            .isTrue();
                }

                currentIndex += groupSize;
            }
        }

        return this;
    }

    /**
     * Compares two callbacks, ignoring the timestamp field.
     */
    private boolean compareCallbacks(WebhookCallback actual, WebhookCallback expected) {
        try {
            Assertions.assertThat(actual)
                    .usingRecursiveComparison()
                    .ignoringFields("timestamp")
                    .isEqualTo(expected);
            return true;
        } catch (AssertionError e) {
            return false;
        }
    }
}
