package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import org.testcontainers.utility.DockerImageName;

import java.util.Objects;

/**
 * Immutable identity of a Docker image selected for one transition phase.
 *
 * @param requestedName repository and tag requested by configuration
 * @param canonicalName resolved name passed to Testcontainers
 * @param imageId immutable Docker content ID used to distinguish Previous from Candidate
 */
public record ResolvedImage(DockerImageName requestedName, String canonicalName, String imageId) {

    /** Validates that every form of the resolved image identity is present. */
    public ResolvedImage {
        Objects.requireNonNull(requestedName, "requestedName");
        Objects.requireNonNull(canonicalName, "canonicalName");
        Objects.requireNonNull(imageId, "imageId");
    }
}
