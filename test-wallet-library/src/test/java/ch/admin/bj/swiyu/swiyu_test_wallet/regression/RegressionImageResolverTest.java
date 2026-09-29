package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import org.junit.jupiter.api.Test;
import org.testcontainers.utility.DockerImageName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class RegressionImageResolverTest {

    private static final String BASE_IMAGE = "registry.example/component";

    @Test
    void resolvePair_whenTagsResolveToSameImage_thenRejectsTransition() {
        final RegressionImageResolver resolver = resolver("sha256:same", "sha256:same");

        assertThatIllegalArgumentException()
                .isThrownBy(() -> resolver.resolvePair("issuer", BASE_IMAGE, versions()))
                .withMessageContaining("resolve to the same image")
                .withMessageContaining("sha256:same");
    }

    @Test
    void resolvePair_whenImagesAreDistinct_thenReturnsBothResolvedImages() {
        final RegressionImageResolver resolver = resolver("sha256:previous", "sha256:candidate");

        final RegressionImageResolver.ResolvedPair pair =
                resolver.resolvePair("verifier", BASE_IMAGE, versions());

        assertThat(pair.previous().imageId()).isEqualTo("sha256:previous");
        assertThat(pair.candidate().imageId()).isEqualTo("sha256:candidate");
    }

    private static RegressionImageResolver resolver(
            final String previousImageId,
            final String candidateImageId) {
        return new RegressionImageResolver() {
            @Override
            public ResolvedImage resolve(final String baseImage, final String version) {
                final String imageId = "4.1.0".equals(version) ? previousImageId : candidateImageId;
                return new ResolvedImage(
                        DockerImageName.parse(baseImage).withTag(version),
                        baseImage + ":" + version,
                        imageId
                );
            }
        };
    }

    private static RegressionImageResolver.RequestedVersions versions() {
        return new RegressionImageResolver.RequestedVersions("4.1.0", "4.2.0");
    }
}
