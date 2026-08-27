package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerHandle;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerRuntimeFactory;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import org.testcontainers.utility.MountableFile;

import java.util.function.Function;

/**
 * Stateful Issuer upgrade from Previous to Candidate on one logical identity and database schema.
 *
 * <p>The transition creates the status list on Previous and rebinds that same persisted list to Candidate. It owns the
 * active Issuer container and its regression schema, but not shared PostgreSQL or MockServer containers. Use it from a
 * try-with-resources block and follow {@code startPrevious -> preparePrevious -> upgradeToCandidate}. This type is not
 * thread-safe.
 */
public final class IssuerVersionTransition implements AutoCloseable {

    private final VersionedComponent<IssuerVariant> previousDescriptor;
    private final VersionedComponent<IssuerVariant> candidateDescriptor;
    private final RegressionSchema schema;
    private final VersionTransitionLifecycle<IssuerHandle> lifecycle;
    private StatusList persistedStatusList;

    IssuerVersionTransition(
            final VersionedComponent<IssuerVariant> previous,
            final VersionedComponent<IssuerVariant> candidate,
            final IssuerRuntimeFactory runtimeFactory,
            final IssuerConfig logicalConfig,
            final IssuerImageConfig previousImageConfig,
            final IssuerImageConfig candidateImageConfig,
            final MountableFile previousMetadata,
            final MountableFile candidateMetadata,
            final RegressionSchema schema) {
        this.previousDescriptor = previous;
        this.candidateDescriptor = candidate;
        this.schema = schema;

        this.lifecycle = new VersionTransitionLifecycle<>(
                () -> runtimeFactory.start(new IssuerRuntimeFactory.StartRequest(
                        previousDescriptor.variant(),
                        logicalConfig,
                        previousImageConfig,
                        previousDescriptor.image().canonicalName(),
                        previousMetadata,
                        null
                )),
                () -> runtimeFactory.start(new IssuerRuntimeFactory.StartRequest(
                        candidateDescriptor.variant(),
                        logicalConfig,
                        candidateImageConfig,
                        candidateDescriptor.image().canonicalName(),
                        candidateMetadata,
                        persistedStatusList
                )),
                IssuerVersionTransition::stop,
                schema::remove
        );
    }

    /**
     * Starts Previous and captures the status list that Candidate must reuse.
     *
     * @return the runtime handle used to create historical Issuer artifacts
     * @throws IllegalStateException if this transition is not in {@link TransitionState#CREATED}, or Previous does not
     * expose the status list required by Candidate
     */
    public IssuerHandle startPrevious() {
        final IssuerHandle previous = lifecycle.startPrevious();
        persistedStatusList = previous.statusList();
        if (persistedStatusList == null) {
            lifecycle.rejectPrevious();
            throw new IllegalStateException(
                    "Previous Issuer did not expose the status list required by Candidate"
            );
        }
        return previous;
    }

    /**
     * Creates a historical artifact while Previous is still running.
     *
     * <p>Candidate cannot start until this callback succeeds. If it fails, Previous remains active and preparation may
     * be retried or the transition may be closed.
     *
     * @param preparation operation that persists an offer, credential or other historical artifact
     * @param <T> artifact type passed by the test to its Candidate phase
     * @return the artifact returned by {@code preparation}
     * @throws IllegalStateException if Previous is not running or was already prepared
     */
    public <T> T preparePrevious(final Function<? super IssuerHandle, ? extends T> preparation) {
        return lifecycle.preparePrevious(preparation);
    }

    /**
     * Stops Previous and starts Candidate with the same identity, schema and status list.
     *
     * @return a newly assembled Candidate runtime handle
     * @throws IllegalStateException if successful preparation has not completed
     */
    public IssuerHandle upgradeToCandidate() {
        return lifecycle.upgradeToCandidate();
    }

    public TransitionState state() {
        return lifecycle.state();
    }

    public VersionedComponent<IssuerVariant> previous() {
        return previousDescriptor;
    }

    public VersionedComponent<IssuerVariant> candidate() {
        return candidateDescriptor;
    }

    public String schemaName() {
        return schema.schemaName();
    }

    /**
     * Stops the active Issuer, then removes only this transition's schema.
     *
     * <p>Successful cleanup is idempotent. If stopping or schema removal fails, another call retries the incomplete step.
     */
    @Override
    public void close() {
        lifecycle.close();
    }

    private static void stop(final IssuerHandle handle) {
        if (handle != null && handle.container().isRunning()) {
            handle.container().stop();
        }
    }

}
