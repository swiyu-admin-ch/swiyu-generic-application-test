package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import java.util.Objects;

/**
 * Observable descriptor of one configured side of a transition.
 *
 * @param version configured component image tag
 * @param variant functional Application Tests variant applied to that image
 * @param metadata original metadata source location used for diagnostics and reporting
 * @param image exact resolved Docker image identity
 * @param <V> Issuer or Verifier variant type
 */
public record VersionedComponent<V extends Enum<V>>(
        String version,
        V variant,
        String metadata,
        ResolvedImage image) {

    /** Validates that the phase descriptor is complete. */
    public VersionedComponent {
        Objects.requireNonNull(version, "version");
        Objects.requireNonNull(variant, "variant");
        Objects.requireNonNull(metadata, "metadata");
        Objects.requireNonNull(image, "image");
    }
}
