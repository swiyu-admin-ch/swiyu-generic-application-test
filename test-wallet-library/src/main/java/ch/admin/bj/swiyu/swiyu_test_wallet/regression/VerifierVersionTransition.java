package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierHandle;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierRuntimeFactory;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import org.testcontainers.utility.MountableFile;

import java.util.function.Function;

/**
 * Stateful Verifier upgrade from Previous to Candidate on one logical identity and database schema.
 *
 * <p>The transition owns the active Verifier container and its regression schema, but not shared PostgreSQL or
 * MockServer containers. Use it from a try-with-resources block and follow
 * {@code startPrevious -> preparePrevious -> upgradeToCandidate}. This type is not thread-safe.
 */
public final class VerifierVersionTransition implements AutoCloseable {

    private final VersionedComponent<VerifierVariant> previousDescriptor;
    private final VersionedComponent<VerifierVariant> candidateDescriptor;
    private final RegressionSchema schema;
    private final VersionTransitionLifecycle<VerifierHandle> lifecycle;

    VerifierVersionTransition(
            final VersionedComponent<VerifierVariant> previous,
            final VersionedComponent<VerifierVariant> candidate,
            final VerifierRuntimeFactory runtimeFactory,
            final VerifierConfig logicalConfig,
            final VerifierImageConfig previousImageConfig,
            final VerifierImageConfig candidateImageConfig,
            final MountableFile previousMetadata,
            final MountableFile candidateMetadata,
            final RegressionSchema schema) {
        this.previousDescriptor = previous;
        this.candidateDescriptor = candidate;
        this.schema = schema;
        this.lifecycle = new VersionTransitionLifecycle<>(
                () -> runtimeFactory.start(new VerifierRuntimeFactory.StartRequest(
                        previousDescriptor.variant(),
                        logicalConfig,
                        previousImageConfig,
                        previousDescriptor.image().canonicalName(),
                        previousMetadata
                )),
                () -> runtimeFactory.start(new VerifierRuntimeFactory.StartRequest(
                        candidateDescriptor.variant(),
                        logicalConfig,
                        candidateImageConfig,
                        candidateDescriptor.image().canonicalName(),
                        candidateMetadata
                )),
                VerifierVersionTransition::stop,
                schema::remove
        );
    }

    /**
     * Starts Previous on the transition-owned schema.
     *
     * @return the runtime handle used to create historical Verifier artifacts
     * @throws IllegalStateException if this transition is not in {@link TransitionState#CREATED}
     */
    public VerifierHandle startPrevious() {
        return lifecycle.startPrevious();
    }

    /**
     * Creates a historical artifact while Previous is still running.
     *
     * <p>Candidate cannot start until this callback succeeds. If it fails, Previous remains active and preparation may
     * be retried or the transition may be closed.
     *
     * @param preparation operation that persists a verification request or another historical artifact
     * @param <T> artifact type passed by the test to its Candidate phase
     * @return the artifact returned by {@code preparation}
     * @throws IllegalStateException if Previous is not running or was already prepared
     */
    public <T> T preparePrevious(final Function<? super VerifierHandle, ? extends T> preparation) {
        return lifecycle.preparePrevious(preparation);
    }

    /**
     * Stops Previous and starts Candidate with the same Verifier identity and schema.
     *
     * @return a newly assembled Candidate runtime handle
     * @throws IllegalStateException if successful preparation has not completed
     */
    public VerifierHandle upgradeToCandidate() {
        return lifecycle.upgradeToCandidate();
    }

    public TransitionState state() {
        return lifecycle.state();
    }

    public VersionedComponent<VerifierVariant> previous() {
        return previousDescriptor;
    }

    public VersionedComponent<VerifierVariant> candidate() {
        return candidateDescriptor;
    }

    public String schemaName() {
        return schema.schemaName();
    }

    /**
     * Stops the active Verifier, then removes only this transition's schema.
     *
     * <p>Successful cleanup is idempotent. If stopping or schema removal fails, another call retries the incomplete step.
     */
    @Override
    public void close() {
        lifecycle.close();
    }

    private static void stop(final VerifierHandle handle) {
        if (handle != null && handle.container().isRunning()) {
            handle.container().stop();
        }
    }
}
