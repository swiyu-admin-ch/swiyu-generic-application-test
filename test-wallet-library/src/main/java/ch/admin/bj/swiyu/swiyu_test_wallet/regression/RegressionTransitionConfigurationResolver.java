package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.RegressionProperties;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;

import java.util.Locale;
import java.util.Objects;
import java.util.function.Predicate;

/**
 * Converts mutable Spring-bound regression properties into validated, immutable transition descriptors.
 *
 * <p>Issuer and Verifier settings are resolved independently so an Issuer-only regression does not require valid
 * Verifier settings. Resource resolution and container startup remain separate concerns.
 */
final class RegressionTransitionConfigurationResolver {

    private final RegressionProperties properties;

    RegressionTransitionConfigurationResolver(final RegressionProperties properties) {
        this.properties = Objects.requireNonNull(properties, "properties");
    }

    ResolvedTransition<IssuerVariant> requireIssuerTransition() {
        return resolveTransition(
                "issuer",
                properties.getIssuer(),
                IssuerVariant.class,
                IssuerVariant::requiresHsm
        );
    }

    ResolvedTransition<VerifierVariant> requireVerifierTransition() {
        return resolveTransition(
                "verifier",
                properties.getVerifier(),
                VerifierVariant.class,
                VerifierVariant::requiresHsm
        );
    }

    private static <V extends Enum<V>> ResolvedTransition<V> resolveTransition(
            final String component,
            final RegressionProperties.ComponentTransition transition,
            final Class<V> variantType,
            final Predicate<V> requiresHsm) {
        if (transition == null) {
            throw new IllegalArgumentException("Regression %s transition is missing".formatted(component));
        }

        final ResolvedComponent<V> previous = resolveComponent(
                component,
                "previous",
                transition.getPrevious(),
                variantType,
                requiresHsm
        );
        final ResolvedComponent<V> candidate = resolveComponent(
                component,
                "candidate",
                transition.getCandidate(),
                variantType,
                requiresHsm
        );

        if (previous.version().equals(candidate.version())) {
            throw new IllegalArgumentException(
                    "Regression %s previous and candidate versions must be different".formatted(component)
            );
        }

        return new ResolvedTransition<>(previous, candidate);
    }

    private static <V extends Enum<V>> ResolvedComponent<V> resolveComponent(
            final String component,
            final String phase,
            final RegressionProperties.ComponentVersion configured,
            final Class<V> variantType,
            final Predicate<V> requiresHsm) {
        if (configured == null) {
            throw new IllegalArgumentException(
                    "Regression %s %s configuration is missing".formatted(component, phase)
            );
        }

        final String version = requireText(configured.getVersion(), component, phase, "version");
        final String metadata = requireText(configured.getMetadata(), component, phase, "metadata");
        final String configuredVariant = requireText(configured.getVariant(), component, phase, "variant");
        final V variant;
        try {
            variant = Enum.valueOf(
                    variantType,
                    configuredVariant.toUpperCase(Locale.ROOT).replace('-', '_')
            );
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException(
                    "Unknown regression %s %s variant: %s".formatted(component, phase, configuredVariant),
                    exception
            );
        }

        if (requiresHsm.test(variant)) {
            throw new IllegalArgumentException(
                    "HSM is not supported for regression %s %s".formatted(component, phase)
            );
        }

        return new ResolvedComponent<>(version, variant, metadata);
    }

    private static String requireText(
            final String value,
            final String component,
            final String phase,
            final String property) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                    "Regression %s %s %s must not be blank".formatted(component, phase, property)
            );
        }
        return value.trim();
    }

    /** A validated Previous/Candidate pair for one component. */
    record ResolvedTransition<V extends Enum<V>>(
            ResolvedComponent<V> previous,
            ResolvedComponent<V> candidate) {

        ResolvedTransition {
            Objects.requireNonNull(previous, "previous");
            Objects.requireNonNull(candidate, "candidate");
        }
    }

    /** A validated version descriptor whose variant has been converted to its domain enum. */
    record ResolvedComponent<V extends Enum<V>>(
            String version,
            V variant,
            String metadata) {

        ResolvedComponent {
            Objects.requireNonNull(version, "version");
            Objects.requireNonNull(variant, "variant");
            Objects.requireNonNull(metadata, "metadata");
        }
    }
}
