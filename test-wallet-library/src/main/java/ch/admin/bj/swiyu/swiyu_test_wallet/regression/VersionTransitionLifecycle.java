package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Enforces the ordered replacement of one active runtime handle by another.
 *
 * <p>The lifecycle owns at most one handle. It stops Previous before starting Candidate and delegates persistent
 * resource cleanup to the supplied callback. Failed post-start validation retains the active handle in
 * {@link TransitionState#PREVIOUS_INVALID}; a failed Candidate start leaves the lifecycle in
 * {@link TransitionState#PREVIOUS_STOPPED}. Callers must close either failure state rather than retrying an ambiguous
 * transition. Cleanup and stop failures are retryable through another {@link #close()} call.
 *
 * <p>This type is intentionally not thread-safe.
 */
final class VersionTransitionLifecycle<H> implements AutoCloseable {

    private final Supplier<H> previousStarter;
    private final Supplier<H> candidateStarter;
    private final Consumer<H> stopper;
    private final Runnable cleanup;

    private TransitionState currentState = TransitionState.CREATED;
    private Optional<H> activeHandle = Optional.empty();
    private boolean closing;

    VersionTransitionLifecycle(
            final Supplier<H> previousStarter,
            final Supplier<H> candidateStarter,
            final Consumer<H> stopper,
            final Runnable cleanup) {
        this.previousStarter = Objects.requireNonNull(previousStarter, "previousStarter");
        this.candidateStarter = Objects.requireNonNull(candidateStarter, "candidateStarter");
        this.stopper = Objects.requireNonNull(stopper, "stopper");
        this.cleanup = Objects.requireNonNull(cleanup, "cleanup");
    }

    TransitionState state() {
        return currentState;
    }

    H startPrevious() {
        requireState(TransitionState.CREATED, "start Previous");

        final H previous = Objects.requireNonNull(
                previousStarter.get(),
                "previousStarter returned null"
        );
        activeHandle = Optional.of(previous);
        currentState = TransitionState.PREVIOUS_RUNNING;
        return previous;
    }

    <T> T preparePrevious(final Function<? super H, ? extends T> preparation) {
        requireState(TransitionState.PREVIOUS_RUNNING, "prepare Previous");
        Objects.requireNonNull(preparation, "preparation");

        final T artifact = preparation.apply(requireActiveHandle());
        currentState = TransitionState.PREVIOUS_PREPARED;
        return artifact;
    }

    void rejectPrevious() {
        requireState(TransitionState.PREVIOUS_RUNNING, "reject Previous");
        currentState = TransitionState.PREVIOUS_INVALID;
    }

    H upgradeToCandidate() {
        requireState(TransitionState.PREVIOUS_PREPARED, "upgrade to Candidate");

        stopPrevious();

        final H candidate = Objects.requireNonNull(
                candidateStarter.get(),
                "candidateStarter returned null"
        );
        activeHandle = Optional.of(candidate);
        currentState = TransitionState.CANDIDATE_RUNNING;
        return candidate;
    }

    private void stopPrevious() {
        stopper.accept(requireActiveHandle());
        activeHandle = Optional.empty();
        currentState = TransitionState.PREVIOUS_STOPPED;
    }

    @Override
    public void close() {
        if (currentState == TransitionState.CLOSED) {
            return;
        }

        closing = true;
        if (activeHandle.isPresent()) {
            stopper.accept(requireActiveHandle());
            activeHandle = Optional.empty();
        }

        cleanup.run();
        currentState = TransitionState.CLOSED;
    }

    private H requireActiveHandle() {
        return activeHandle.orElseThrow(() -> new IllegalStateException(
                "Transition %s has no active runtime".formatted(currentState)
        ));
    }

    private void requireState(final TransitionState requiredState, final String operation) {
        if (closing || currentState != requiredState) {
            throw new IllegalStateException(
                    "Cannot %s while transition is %s%s; expected %s"
                            .formatted(operation, currentState, closing ? " (closing)" : "", requiredState)
            );
        }
    }
}
