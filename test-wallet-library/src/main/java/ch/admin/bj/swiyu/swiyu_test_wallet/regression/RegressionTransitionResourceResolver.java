package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import org.testcontainers.utility.MountableFile;

import java.util.Objects;

/** Resolves metadata and immutable Docker image identities before a transition can own runtime resources. */
final class RegressionTransitionResourceResolver {

    private final RegressionImageResolver imageResolver;

    RegressionTransitionResourceResolver(final RegressionImageResolver imageResolver) {
        this.imageResolver = Objects.requireNonNull(imageResolver, "imageResolver");
    }

    <V extends Enum<V>> ResolvedTransitionResources<V> resolve(
            final String component,
            final String baseImage,
            final RegressionTransitionConfigurationResolver.ResolvedTransition<V> configured) {
        final MetadataSource previousMetadata = MetadataSource.resolve(configured.previous().metadata());
        final MetadataSource candidateMetadata = MetadataSource.resolve(configured.candidate().metadata());
        final RegressionImageResolver.ResolvedPair images = imageResolver.resolvePair(
                component,
                baseImage,
                new RegressionImageResolver.RequestedVersions(
                        configured.previous().version(),
                        configured.candidate().version()
                )
        );

        return new ResolvedTransitionResources<>(
                component(configured.previous(), images.previous()),
                component(configured.candidate(), images.candidate()),
                previousMetadata.mountableFile(),
                candidateMetadata.mountableFile()
        );
    }

    private static <V extends Enum<V>> VersionedComponent<V> component(
            final RegressionTransitionConfigurationResolver.ResolvedComponent<V> configured,
            final ResolvedImage image) {
        return new VersionedComponent<>(
                configured.version(),
                configured.variant(),
                configured.metadata(),
                image
        );
    }

    /** Runtime-ready resources for both sides of a validated transition. */
    record ResolvedTransitionResources<V extends Enum<V>>(
            VersionedComponent<V> previous,
            VersionedComponent<V> candidate,
            MountableFile previousMetadata,
            MountableFile candidateMetadata) {

        ResolvedTransitionResources {
            Objects.requireNonNull(previous, "previous");
            Objects.requireNonNull(candidate, "candidate");
            Objects.requireNonNull(previousMetadata, "previousMetadata");
            Objects.requireNonNull(candidateMetadata, "candidateMetadata");
        }
    }
}
