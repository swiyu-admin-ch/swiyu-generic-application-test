/**
 * Orchestrates stateful compatibility checks between a Previous component image and a Candidate image.
 *
 * <p>The subsystem separates four concerns:
 *
 * <ul>
 *   <li>Spring properties hold external values without starting or resolving resources.</li>
 *   <li>Configuration and resource resolvers validate variants, metadata and Docker image identities eagerly.</li>
 *   <li>Component-specific factories preserve one logical identity and one PostgreSQL schema across both versions.</li>
 *   <li>Version transitions enforce preparation, replacement and exact cleanup of the owned runtime resources.</li>
 * </ul>
 *
 * <p>PostgreSQL and MockServer are shared environment services and outlive a transition. The component container and
 * its uniquely named schema belong to the transition and are released by {@link java.lang.AutoCloseable#close()}.
 */
package ch.admin.bj.swiyu.swiyu_test_wallet.regression;
