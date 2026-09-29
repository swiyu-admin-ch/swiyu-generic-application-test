package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.RegressionProperties;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerRuntimeFactory;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierRuntimeFactory;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.Objects;

/**
 * Entry point for creating isolated Previous-to-Candidate component transitions.
 *
 * <p>Each method validates and resolves only the requested component, including both metadata files and Docker images.
 * Creating a transition allocates an owned schema name but starts no component container; callers start the Previous
 * runtime explicitly through the returned transition and must close it to release the schema.
 */
public final class RegressionEnvironmentFactory {

    private final IssuerTransitionFactory issuerTransitions;
    private final VerifierTransitionFactory verifierTransitions;

    /**
     * Creates the transition façade without validating configuration or starting containers.
     *
     * @param properties raw Spring-bound Previous/Candidate settings
     * @param issuerImageTemplate standard Issuer image settings copied for each phase
     * @param verifierImageTemplate standard Verifier image settings copied for each phase
     * @param issuerRuntimeFactory physical Issuer runtime assembler
     * @param verifierRuntimeFactory physical Verifier runtime assembler
     * @param database shared PostgreSQL container that will host transition-owned schemas
     * @param imageResolver Docker image resolver used lazily for the requested component
     */
    public RegressionEnvironmentFactory(
            final RegressionProperties properties,
            final IssuerImageConfig issuerImageTemplate,
            final VerifierImageConfig verifierImageTemplate,
            final IssuerRuntimeFactory issuerRuntimeFactory,
            final VerifierRuntimeFactory verifierRuntimeFactory,
            final PostgreSQLContainer<?> database,
            final RegressionImageResolver imageResolver) {
        final RegressionTransitionConfigurationResolver configurationResolver =
                new RegressionTransitionConfigurationResolver(Objects.requireNonNull(properties, "properties"));
        final RegressionTransitionResourceResolver resourceResolver =
                new RegressionTransitionResourceResolver(Objects.requireNonNull(imageResolver, "imageResolver"));

        issuerTransitions = new IssuerTransitionFactory(
                configurationResolver,
                resourceResolver,
                issuerImageTemplate,
                issuerRuntimeFactory,
                database
        );
        verifierTransitions = new VerifierTransitionFactory(
                configurationResolver,
                resourceResolver,
                verifierImageTemplate,
                verifierRuntimeFactory,
                database
        );
    }

    /**
     * Resolves an Issuer transition without validating, resolving or starting a Verifier.
     *
     * @return a new transition owning one unique Issuer schema name
     */
    public IssuerVersionTransition issuerTransition() {
        return issuerTransitions.create();
    }

    /**
     * Resolves a Verifier transition without validating, resolving or starting an Issuer.
     *
     * @return a new transition owning one unique Verifier schema name
     */
    public VerifierVersionTransition verifierTransition() {
        return verifierTransitions.create();
    }
}
