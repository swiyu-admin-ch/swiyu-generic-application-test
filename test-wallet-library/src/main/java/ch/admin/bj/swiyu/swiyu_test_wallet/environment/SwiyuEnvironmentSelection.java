package ch.admin.bj.swiyu.swiyu_test_wallet.environment;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

public record SwiyuEnvironmentSelection(
        Set<IssuerVariant> issuers,
        Set<VerifierVariant> verifiers,
        boolean keycloak,
        boolean hsm
) {

    public static SwiyuEnvironmentSelection from(final Class<?> testClass) {
        final UseIssuers useIssuers = testClass.getAnnotation(UseIssuers.class);
        final UseVerifiers useVerifiers = testClass.getAnnotation(UseVerifiers.class);
        final UseSharedServices sharedServices = testClass.getAnnotation(UseSharedServices.class);

        final Set<IssuerVariant> issuerVariants = new LinkedHashSet<>(Arrays.asList(
                useIssuers == null ? new IssuerVariant[]{IssuerVariant.DEFAULT} : useIssuers.value()
        ));
        final Set<VerifierVariant> verifierVariants = new LinkedHashSet<>(Arrays.asList(
                useVerifiers == null ? new VerifierVariant[]{VerifierVariant.DEFAULT} : useVerifiers.value()
        ));

        boolean keycloakRequired = sharedServices != null && sharedServices.keycloak();
        boolean hsmRequired = sharedServices != null && sharedServices.hsm();

        keycloakRequired = keycloakRequired
                || issuerVariants.stream().anyMatch(IssuerVariant::requiresKeycloak)
                || verifierVariants.stream().anyMatch(VerifierVariant::requiresKeycloak);
        hsmRequired = hsmRequired
                || issuerVariants.stream().anyMatch(IssuerVariant::requiresHsm)
                || verifierVariants.stream().anyMatch(VerifierVariant::requiresHsm);

        return new SwiyuEnvironmentSelection(issuerVariants, verifierVariants, keycloakRequired, hsmRequired);
    }

    public IssuerVariant primaryIssuer() {
        return issuers.iterator().next();
    }

    public VerifierVariant primaryVerifier() {
        return verifiers.iterator().next();
    }
}
