package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import com.github.dockerjava.api.command.InspectImageResponse;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.images.RemoteDockerImage;
import org.testcontainers.utility.DockerImageName;

import java.util.Objects;

/** Resolves configured Docker tags to the exact local image identities used by a regression run. */
public class RegressionImageResolver {

    /** Creates a resolver backed by the Testcontainers Docker client. */
    public RegressionImageResolver() {
    }

    /**
     * Pulls an image when necessary, then inspects its content identity.
     *
     * @param baseImage repository name without a tag
     * @param version configured image tag
     * @return requested name, canonical resolved name and immutable Docker image ID
     * @throws IllegalStateException if Docker cannot resolve or inspect the image
     */
    public ResolvedImage resolve(final String baseImage, final String version) {
        final DockerImageName requested = DockerImageName.parse(baseImage).withTag(version);
        requested.assertValid();

        final String canonicalName = new RemoteDockerImage(requested).get();
        final InspectImageResponse inspected = DockerClientFactory.instance()
                .client()
                .inspectImageCmd(canonicalName)
                .exec();
        if (inspected.getId() == null || inspected.getId().isBlank()) {
            throw new IllegalStateException("Docker did not return an image ID for " + canonicalName);
        }
        return new ResolvedImage(requested, canonicalName, inspected.getId());
    }

    /**
     * Resolves both sides before any component starts and rejects aliases of the same image content.
     *
     * @param component component name used in validation errors
     * @param baseImage repository name without a tag
     * @param versions configured tags for the two transition phases
     * @return exact Previous and Candidate image identities
     * @throws IllegalArgumentException if Previous and Candidate resolve to the same Docker image ID
     */
    public ResolvedPair resolvePair(
            final String component,
            final String baseImage,
            final RequestedVersions versions) {
        final ResolvedImage previous = resolve(baseImage, versions.previous());
        final ResolvedImage candidate = resolve(baseImage, versions.candidate());
        if (previous.imageId().equals(candidate.imageId())) {
            throw new IllegalArgumentException(
                    "Regression %s previous and candidate resolve to the same image: %s"
                            .formatted(component, previous.imageId())
            );
        }
        return new ResolvedPair(previous, candidate);
    }

    /**
     * Configured Docker tags requested for a version transition.
     *
     * @param previous tag of the released component that created the historical state
     * @param candidate tag of the component being evaluated for release
     */
    public record RequestedVersions(String previous, String candidate) {

        /** Rejects incomplete image selections before Docker is accessed. */
        public RequestedVersions {
            requireVersion(previous, "previous");
            requireVersion(candidate, "candidate");
        }

        private static void requireVersion(final String version, final String phase) {
            if (version == null || version.isBlank()) {
                throw new IllegalArgumentException(phase + " version must not be blank");
            }
        }
    }

    /**
     * Exact Docker images selected for both transition phases.
     *
     * @param previous exact image used by Previous
     * @param candidate exact image used by Candidate
     */
    public record ResolvedPair(ResolvedImage previous, ResolvedImage candidate) {

        /** Validates that both phase images are present. */
        public ResolvedPair {
            Objects.requireNonNull(previous, "previous");
            Objects.requireNonNull(candidate, "candidate");
        }
    }
}
