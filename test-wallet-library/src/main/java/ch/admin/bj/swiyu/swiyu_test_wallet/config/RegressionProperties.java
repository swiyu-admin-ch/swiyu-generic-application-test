package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Mutable Spring binding model for Previous-to-Candidate regression settings.
 *
 * <p>This type deliberately contains no runtime validation or Testcontainers concerns. The regression subsystem
 * validates only the component transition requested by a test, keeping Issuer and Verifier configuration independent.
 */
@ConfigurationProperties("regression")
@SuppressWarnings("PMD.DataClass")
public class RegressionProperties {

    private static final String DEFAULT_ISSUER_METADATA = "classpath:issuer/metadata.json";
    private static final String DEFAULT_VERIFIER_METADATA = "classpath:verifier/metadata.json";

    private ComponentTransition issuer = new ComponentTransition(DEFAULT_ISSUER_METADATA);
    private ComponentTransition verifier = new ComponentTransition(DEFAULT_VERIFIER_METADATA);

    public ComponentTransition getIssuer() {
        return issuer;
    }

    public void setIssuer(final ComponentTransition issuer) {
        this.issuer = issuer;
    }

    public ComponentTransition getVerifier() {
        return verifier;
    }

    public void setVerifier(final ComponentTransition verifier) {
        this.verifier = verifier;
    }

    /** Configuration pair bound for one component without resolving its variant or resources. */
    @SuppressWarnings("PMD.DataClass")
    public static class ComponentTransition {

        private ComponentVersion previous;
        private ComponentVersion candidate;

        public ComponentTransition() {
            this(null);
        }

        private ComponentTransition(final String defaultMetadata) {
            previous = new ComponentVersion(defaultMetadata);
            candidate = new ComponentVersion(defaultMetadata);
        }

        public ComponentVersion getPrevious() {
            return previous;
        }

        public void setPrevious(final ComponentVersion previous) {
            this.previous = previous;
        }

        public ComponentVersion getCandidate() {
            return candidate;
        }

        public void setCandidate(final ComponentVersion candidate) {
            this.candidate = candidate;
        }
    }

    /** Raw version, variant and metadata values for one side of a transition. */
    @SuppressWarnings("PMD.DataClass")
    public static class ComponentVersion {

        private String version;
        private String variant = "DEFAULT";
        private String metadata;

        public ComponentVersion() {
        }

        private ComponentVersion(final String defaultMetadata) {
            metadata = defaultMetadata;
        }

        public String getVersion() {
            return version;
        }

        public void setVersion(final String version) {
            this.version = version;
        }

        public String getVariant() {
            return variant;
        }

        public void setVariant(final String variant) {
            this.variant = variant;
        }

        public String getMetadata() {
            return metadata;
        }

        public void setMetadata(final String metadata) {
            this.metadata = metadata;
        }
    }

}
