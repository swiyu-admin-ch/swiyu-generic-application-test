package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.RegressionProperties;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RegressionTransitionConfigurationResolverTest {

    private static final String PREVIOUS_VERSION = "4.1.0";
    private static final String CANDIDATE_VERSION = "4.2.0";

    @Test
    void issuerConfiguration_whenValid_thenResolvesImmutableDescriptors() {
        final RegressionProperties properties = issuerProperties(" " + PREVIOUS_VERSION + " ", CANDIDATE_VERSION);
        properties.getIssuer().getPrevious().setVariant("signed-metadata");

        final RegressionTransitionConfigurationResolver.ResolvedTransition<IssuerVariant> resolved =
                resolver(properties).requireIssuerTransition();

        assertThat(resolved.previous().version()).isEqualTo(PREVIOUS_VERSION);
        assertThat(resolved.previous().variant()).isEqualTo(IssuerVariant.SIGNED_METADATA);
        assertThat(resolved.previous().metadata()).isEqualTo("classpath:issuer/metadata.json");
        assertThat(resolved.candidate().version()).isEqualTo(CANDIDATE_VERSION);
        assertThat(resolved.candidate().variant()).isEqualTo(IssuerVariant.DEFAULT);
    }

    @Test
    void issuerResolution_whenVerifierConfigurationIsInvalid_thenValidatesOnlyIssuer() {
        final RegressionProperties properties = issuerProperties(PREVIOUS_VERSION, CANDIDATE_VERSION);
        properties.getVerifier().getPrevious().setVariant("HSM");

        final RegressionTransitionConfigurationResolver resolver = resolver(properties);

        assertThatCode(resolver::requireIssuerTransition).doesNotThrowAnyException();
        assertThatThrownBy(resolver::requireVerifierTransition)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("verifier previous version must not be blank");
    }

    @Test
    void issuerVersions_whenBlankOrEqual_thenRejectsTransition() {
        final RegressionTransitionConfigurationResolver blank =
                resolver(issuerProperties(" ", CANDIDATE_VERSION));
        final RegressionTransitionConfigurationResolver equal =
                resolver(issuerProperties(CANDIDATE_VERSION, " " + CANDIDATE_VERSION + " "));

        assertThatThrownBy(blank::requireIssuerTransition)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("issuer previous version must not be blank");
        assertThatThrownBy(equal::requireIssuerTransition)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("previous and candidate versions must be different");
    }

    @Test
    void variants_whenUnknownOrHsm_thenRejectsTransition() {
        final RegressionProperties unknown = issuerProperties(PREVIOUS_VERSION, CANDIDATE_VERSION);
        unknown.getIssuer().getCandidate().setVariant("NOT_A_VARIANT");
        final RegressionProperties issuerHsm = issuerProperties(PREVIOUS_VERSION, CANDIDATE_VERSION);
        issuerHsm.getIssuer().getPrevious().setVariant("HSM");
        final RegressionProperties verifierHsm = verifierProperties(PREVIOUS_VERSION, CANDIDATE_VERSION);
        verifierHsm.getVerifier().getCandidate().setVariant("HSM");

        assertThatThrownBy(resolver(unknown)::requireIssuerTransition)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unknown regression issuer candidate variant");
        assertThatThrownBy(resolver(issuerHsm)::requireIssuerTransition)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("HSM is not supported for regression issuer previous");
        assertThatThrownBy(resolver(verifierHsm)::requireVerifierTransition)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("HSM is not supported for regression verifier candidate");
    }

    private static RegressionTransitionConfigurationResolver resolver(final RegressionProperties properties) {
        return new RegressionTransitionConfigurationResolver(properties);
    }

    private static RegressionProperties issuerProperties(final String previous, final String candidate) {
        final RegressionProperties properties = new RegressionProperties();
        properties.getIssuer().getPrevious().setVersion(previous);
        properties.getIssuer().getCandidate().setVersion(candidate);
        return properties;
    }

    private static RegressionProperties verifierProperties(final String previous, final String candidate) {
        final RegressionProperties properties = new RegressionProperties();
        properties.getVerifier().getPrevious().setVersion(previous);
        properties.getVerifier().getCandidate().setVersion(candidate);
        return properties;
    }
}
