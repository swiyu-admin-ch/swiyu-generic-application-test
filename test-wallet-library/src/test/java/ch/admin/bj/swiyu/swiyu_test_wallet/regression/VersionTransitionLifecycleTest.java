package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VersionTransitionLifecycleTest {

    private static final String PREVIOUS = "previous";
    private static final String CANDIDATE = "candidate";
    private static final String START_PREVIOUS = "start:previous";
    private static final String START_CANDIDATE = "start:candidate";
    private static final String CLEANUP = "cleanup";
    private static final int FIRST_ATTEMPT = 1;

    @Test
    void lifecycle_whenCompleted_thenStopsPreviousBeforeStartingCandidate() {
        final List<String> events = new ArrayList<>();
        final VersionTransitionLifecycle<String> lifecycle = new VersionTransitionLifecycle<>(
                () -> recordAndReturn(events, START_PREVIOUS, PREVIOUS),
                () -> recordAndReturn(events, START_CANDIDATE, CANDIDATE),
                handle -> events.add("stop:" + handle),
                () -> events.add(CLEANUP)
        );

        assertThat(lifecycle.state()).isEqualTo(TransitionState.CREATED);

        assertThat(lifecycle.startPrevious()).isEqualTo(PREVIOUS);
        assertThat(lifecycle.state()).isEqualTo(TransitionState.PREVIOUS_RUNNING);

        final String artifact = lifecycle.preparePrevious(previous -> {
            events.add("prepare:" + previous);
            return "historical-offer";
        });

        assertThat(artifact).isEqualTo("historical-offer");
        assertThat(lifecycle.state()).isEqualTo(TransitionState.PREVIOUS_PREPARED);

        assertThat(lifecycle.upgradeToCandidate()).isEqualTo(CANDIDATE);
        assertThat(lifecycle.state()).isEqualTo(TransitionState.CANDIDATE_RUNNING);

        lifecycle.close();

        assertThat(lifecycle.state()).isEqualTo(TransitionState.CLOSED);
        assertThat(events).containsExactly(
                START_PREVIOUS,
                "prepare:previous",
                "stop:previous",
                START_CANDIDATE,
                "stop:candidate",
                CLEANUP
        );
    }

    @Test
    void preparePrevious_whenPreparationFails_thenPreviousKeepsRunningAndUpgradeIsRejected() {
        final List<String> stoppedHandles = new ArrayList<>();
        final AtomicInteger cleanupCalls = new AtomicInteger();
        final VersionTransitionLifecycle<String> lifecycle = new VersionTransitionLifecycle<>(
                () -> PREVIOUS,
                () -> CANDIDATE,
                stoppedHandles::add,
                cleanupCalls::incrementAndGet
        );
        lifecycle.startPrevious();

        assertThatThrownBy(() -> lifecycle.preparePrevious(previous -> {
            throw new IllegalArgumentException("preparation failed");
        }))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("preparation failed");

        assertThat(lifecycle.state()).isEqualTo(TransitionState.PREVIOUS_RUNNING);
        assertThatIllegalStateException()
                .isThrownBy(lifecycle::upgradeToCandidate)
                .withMessageContaining("expected PREVIOUS_PREPARED");
        assertThat(stoppedHandles).isEmpty();

        lifecycle.close();

        assertThat(stoppedHandles).containsExactly(PREVIOUS);
        assertThat(cleanupCalls).hasValue(1);
    }

    @Test
    void upgradeToCandidate_whenCandidateStartupFails_thenRecordsPreviousStoppedAndAllowsCleanup() {
        final List<String> events = new ArrayList<>();
        final VersionTransitionLifecycle<String> lifecycle = new VersionTransitionLifecycle<>(
                () -> recordAndReturn(events, START_PREVIOUS, PREVIOUS),
                () -> {
                    events.add(START_CANDIDATE);
                    throw new IllegalStateException("candidate startup failed");
                },
                handle -> events.add("stop:" + handle),
                () -> events.add(CLEANUP)
        );
        lifecycle.startPrevious();
        lifecycle.preparePrevious(previous -> "historical-artifact");

        assertThatThrownBy(lifecycle::upgradeToCandidate)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("candidate startup failed");

        assertThat(lifecycle.state()).isEqualTo(TransitionState.PREVIOUS_STOPPED);
        assertThatIllegalStateException()
                .isThrownBy(lifecycle::upgradeToCandidate)
                .withMessageContaining("transition is PREVIOUS_STOPPED");

        lifecycle.close();

        assertThat(lifecycle.state()).isEqualTo(TransitionState.CLOSED);
        assertThat(events).containsExactly(
                START_PREVIOUS,
                "stop:previous",
                START_CANDIDATE,
                CLEANUP
        );
    }

    @Test
    void lifecycle_whenOperationsAreOutOfOrder_thenRejectsThem() {
        final VersionTransitionLifecycle<String> lifecycle = new VersionTransitionLifecycle<>(
                () -> PREVIOUS,
                () -> CANDIDATE,
                ignored -> { },
                () -> { }
        );

        assertThatIllegalStateException()
                .isThrownBy(() -> lifecycle.preparePrevious(previous -> "artifact"))
                .withMessageContaining("expected PREVIOUS_RUNNING");
        assertThatIllegalStateException()
                .isThrownBy(lifecycle::upgradeToCandidate)
                .withMessageContaining("expected PREVIOUS_PREPARED");

        lifecycle.startPrevious();

        assertThatIllegalStateException()
                .isThrownBy(lifecycle::startPrevious)
                .withMessageContaining("expected CREATED");

        lifecycle.preparePrevious(previous -> "artifact");

        assertThatIllegalStateException()
                .isThrownBy(() -> lifecycle.preparePrevious(previous -> "another-artifact"))
                .withMessageContaining("expected PREVIOUS_RUNNING");

        lifecycle.close();
    }

    @Test
    void close_whenCalledMoreThanOnce_thenStopsAndCleansUpOnlyOnce() {
        final AtomicInteger stopCalls = new AtomicInteger();
        final AtomicInteger cleanupCalls = new AtomicInteger();
        final VersionTransitionLifecycle<String> lifecycle = new VersionTransitionLifecycle<>(
                () -> PREVIOUS,
                () -> CANDIDATE,
                ignored -> stopCalls.incrementAndGet(),
                cleanupCalls::incrementAndGet
        );
        lifecycle.startPrevious();

        lifecycle.close();
        lifecycle.close();

        assertThat(lifecycle.state()).isEqualTo(TransitionState.CLOSED);
        assertThat(stopCalls).hasValue(1);
        assertThat(cleanupCalls).hasValue(1);
        assertThatIllegalStateException()
                .isThrownBy(lifecycle::startPrevious)
                .withMessageContaining("transition is CLOSED");
    }

    @Test
    void close_whenCleanupFails_thenRetriesCleanupWithoutStoppingAgain() {
        final AtomicInteger stopCalls = new AtomicInteger();
        final AtomicInteger cleanupCalls = new AtomicInteger();
        final VersionTransitionLifecycle<String> lifecycle = new VersionTransitionLifecycle<>(
                () -> PREVIOUS,
                () -> CANDIDATE,
                ignored -> stopCalls.incrementAndGet(),
                () -> {
                    if (cleanupCalls.incrementAndGet() == FIRST_ATTEMPT) {
                        throw new IllegalArgumentException("cleanup failed");
                    }
                }
        );
        lifecycle.startPrevious();

        assertThatThrownBy(lifecycle::close)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("cleanup failed");
        assertThat(stopCalls).hasValue(1);
        assertThat(cleanupCalls).hasValue(1);
        assertThat(lifecycle.state()).isEqualTo(TransitionState.PREVIOUS_RUNNING);
        assertThatIllegalStateException()
                .isThrownBy(() -> lifecycle.preparePrevious(previous -> "artifact"))
                .withMessageContaining("closing");

        lifecycle.close();

        assertThat(stopCalls).hasValue(1);
        assertThat(cleanupCalls).hasValue(2);
        assertThat(lifecycle.state()).isEqualTo(TransitionState.CLOSED);
    }

    @Test
    void close_whenStopFails_thenDoesNotRemoveSchemaAndRetriesStop() {
        final AtomicInteger stopCalls = new AtomicInteger();
        final AtomicInteger cleanupCalls = new AtomicInteger();
        final VersionTransitionLifecycle<String> lifecycle = new VersionTransitionLifecycle<>(
                () -> PREVIOUS,
                () -> CANDIDATE,
                ignored -> {
                    if (stopCalls.incrementAndGet() == FIRST_ATTEMPT) {
                        throw new IllegalStateException("stop failed");
                    }
                },
                cleanupCalls::incrementAndGet
        );
        lifecycle.startPrevious();

        assertThatThrownBy(lifecycle::close)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("stop failed");
        assertThat(cleanupCalls).hasValue(0);

        lifecycle.close();

        assertThat(stopCalls).hasValue(2);
        assertThat(cleanupCalls).hasValue(1);
        assertThat(lifecycle.state()).isEqualTo(TransitionState.CLOSED);
    }

    private static String recordAndReturn(
            final List<String> events,
            final String event,
            final String result) {
        events.add(event);
        return result;
    }
}
