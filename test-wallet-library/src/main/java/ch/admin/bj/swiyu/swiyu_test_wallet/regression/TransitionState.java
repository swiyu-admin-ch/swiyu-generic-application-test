package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

/**
 * Observable lifecycle states for a Previous-to-Candidate transition.
 *
 * <p>The normal path is {@code CREATED -> PREVIOUS_RUNNING -> PREVIOUS_PREPARED -> CANDIDATE_RUNNING -> CLOSED}.
 * {@link #PREVIOUS_INVALID} retains ownership when post-start validation fails. {@link #PREVIOUS_STOPPED} is retained
 * when Candidate startup fails, allowing cleanup without pretending that Previous is still active.
 */
public enum TransitionState {
    /** No component has started. */
    CREATED,
    /** Previous is the active runtime and may be prepared. */
    PREVIOUS_RUNNING,
    /** Previous is active but failed a required post-start invariant; only cleanup remains valid. */
    PREVIOUS_INVALID,
    /** Historical preparation succeeded and Previous is ready to be replaced. */
    PREVIOUS_PREPARED,
    /** Previous stopped, but Candidate failed to become active. */
    PREVIOUS_STOPPED,
    /** Candidate is the active runtime. */
    CANDIDATE_RUNNING,
    /** Active runtime and transition-owned schema were released. */
    CLOSED
}
