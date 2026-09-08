package ch.admin.bj.swiyu.swiyu_test_wallet.environment;

import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import org.mockserver.client.MockServerClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

/**
 * Owns the standard Application Tests component runtimes selected by functional variant.
 *
 * <p>The registry keeps at most one running Issuer and Verifier per variant, starts shared support services on demand,
 * and stops component variants no longer selected by a test environment. It delegates physical runtime assembly to
 * {@link IssuerRuntimeFactory} and {@link VerifierRuntimeFactory}. Stateful Previous-to-Candidate replacements are kept
 * outside this registry because they require explicit image identities and a transition-owned schema lifecycle.
 */
public class SwiyuEnvironmentRegistry {

    private final PostgreSQLContainer<?> dbContainer;
    private final MockServerContainer mockServerContainer;
    private final MockServerClient mockServerClient;
    private final MockServerClientConfig mockServerClientConfig;
    private final TrustConfig trustConfig;
    private final MockAttestationAuthority mockAttestationAuthority;
    private final IssuerImageConfig issuerImageTemplate;
    private final VerifierImageConfig verifierImageTemplate;
    private final IssuerRuntimeFactory issuerRuntimeFactory;
    private final VerifierRuntimeFactory verifierRuntimeFactory;
    private final EnvironmentSupportServices supportServices;

    private final Map<IssuerVariant, IssuerHandle> issuers = new EnumMap<>(IssuerVariant.class);
    private final Map<VerifierVariant, VerifierHandle> verifiers = new EnumMap<>(VerifierVariant.class);

    public SwiyuEnvironmentRegistry(
            final PostgreSQLContainer<?> dbContainer,
            final MockServerContainer mockServerContainer,
            final MockServerClient mockServerClient,
            final MockServerClientConfig mockServerClientConfig,
            final TrustConfig trustConfig,
            final MockAttestationAuthority mockAttestationAuthority,
            final IssuerImageConfig issuerImageTemplate,
            final VerifierImageConfig verifierImageTemplate,
            final IssuerRuntimeFactory issuerRuntimeFactory,
            final VerifierRuntimeFactory verifierRuntimeFactory,
            final EnvironmentSupportServices supportServices) {
        this.dbContainer = dbContainer;
        this.mockServerContainer = mockServerContainer;
        this.mockServerClient = mockServerClient;
        this.mockServerClientConfig = mockServerClientConfig;
        this.trustConfig = trustConfig;
        this.mockAttestationAuthority = mockAttestationAuthority;
        this.issuerImageTemplate = issuerImageTemplate;
        this.verifierImageTemplate = verifierImageTemplate;
        this.issuerRuntimeFactory = issuerRuntimeFactory;
        this.verifierRuntimeFactory = verifierRuntimeFactory;
        this.supportServices = supportServices;
    }

    /**
     * Reconciles the running standard environment with a test's declared selection.
     *
     * <p>Unselected component containers are stopped before missing selections are started. Shared PostgreSQL and
     * MockServer containers must already be running.
     */
    public synchronized void ensureStarted(final SwiyuEnvironmentSelection selection) {
        ensureRunning("database", dbContainer);
        ensureRunning("mockserver", mockServerContainer);
        stopUnselectedIssuers(selection.issuers());
        stopUnselectedVerifiers(selection.verifiers());
        if (selection.hsm()) {
            supportServices.softHsm();
        }
        if (selection.keycloak()) {
            supportServices.keycloak();
        }
        selection.issuers().forEach(this::issuer);
        selection.verifiers().forEach(this::verifier);
        registerTp2Routes(selection.primaryIssuer(), selection.primaryVerifier());
    }

    /** Returns the selected Issuer runtime, starting or recreating it when necessary. */
    public synchronized IssuerHandle issuer(final IssuerVariant variant) {
        final IssuerHandle existingIssuer = issuers.get(variant);
        if (existingIssuer != null && !existingIssuer.container().isRunning()) {
            issuers.remove(variant);
        }
        return issuers.computeIfAbsent(variant, this::startIssuer);
    }

    /** Replaces the cached Issuer handle after creating a new active status list. */
    public synchronized IssuerHandle refreshStatusList(final IssuerVariant variant) {
        final IssuerHandle issuer = issuer(variant);
        final StatusList statusList = issuerRuntimeFactory.createStatusList(issuer.manager(), issuer.jwtKey());
        final IssuerHandle refreshedIssuer = new IssuerHandle(
                issuer.variant(),
                issuer.config(),
                issuer.imageConfig(),
                issuer.container(),
                issuer.manager(),
                issuer.issuanceService(),
                issuer.serviceLocation(),
                statusList,
                issuer.jwtKey(),
                issuer.unauthenticatedJwtKey(),
                issuer.keyId(),
                issuer.managementAuthConfig(),
                issuer.managementAccessToken()
        );
        issuers.put(variant, refreshedIssuer);
        return refreshedIssuer;
    }

    /** Returns the selected Verifier runtime, starting or recreating it when necessary. */
    public synchronized VerifierHandle verifier(final VerifierVariant variant) {
        final VerifierHandle existingVerifier = verifiers.get(variant);
        if (existingVerifier != null && !existingVerifier.container().isRunning()) {
            verifiers.remove(variant);
        }
        return verifiers.computeIfAbsent(variant, this::startVerifier);
    }

    public PostgreSQLContainer<?> dbContainer() {
        return dbContainer;
    }

    public MockServerContainer mockServerContainer() {
        return mockServerContainer;
    }

    public MockServerClient mockServerClient() {
        return mockServerClient;
    }

    public TrustConfig trustConfig() {
        return trustConfig;
    }

    public MockAttestationAuthority mockAttestationAuthority() {
        return mockAttestationAuthority;
    }

    private void stopUnselectedIssuers(final Set<IssuerVariant> selectedVariants) {
        issuers.entrySet().removeIf(entry -> {
            if (selectedVariants.contains(entry.getKey())) {
                return false;
            }
            entry.getValue().container().stop();
            return true;
        });
    }

    private void stopUnselectedVerifiers(final Set<VerifierVariant> selectedVariants) {
        verifiers.entrySet().removeIf(entry -> {
            if (selectedVariants.contains(entry.getKey())) {
                return false;
            }
            entry.getValue().container().stop();
            return true;
        });
    }

    private IssuerHandle startIssuer(final IssuerVariant variant) {
        final IssuerImageConfig imageConfig = variant.imageConfig(issuerImageTemplate);
        final String imageName = imageConfig.getBaseImage() + ":" + imageConfig.getImageTag();
        if (variant.requiresHsm()) {
            // HSM-backed identity creation reads keys exported by the running SoftHSM container.
            supportServices.softHsm();
        }
        final IssuerConfig config = EnvironmentConfig.createIssuerConfig(
                toUri(String.format("https://%s/api/v1/did/%s", MockServerClientConfig.MOCKSERVER_HOST, UUID.randomUUID())),
                imageConfig.isEnableHsm(),
                imageConfig.isEnableHsm() ? supportServices.tokenDirPath() : null
        );
        if (imageConfig.isMultipleSigningKeys()) {
            config.setAdditionalSigningIdentities(List.of(EnvironmentConfig.createIssuerConfig(
                    toUri(String.format(
                            "https://%s/api/v1/did/%s",
                            MockServerClientConfig.MOCKSERVER_HOST,
                            UUID.randomUUID()
                    )),
                    false,
                    null
            )));
        }
        return issuerRuntimeFactory.start(new IssuerRuntimeFactory.StartRequest(
                variant,
                config,
                imageConfig,
                imageName,
                null,
                null
        ));
    }

    private VerifierHandle startVerifier(final VerifierVariant variant) {
        final VerifierImageConfig imageConfig = variant.imageConfig(verifierImageTemplate);
        final String imageName = imageConfig.getBaseImage() + ":" + imageConfig.getImageTag();
        final VerifierConfig config = EnvironmentConfig.createVerifierConfig(
                toUri(String.format("https://%s/api/v1/did/%s", MockServerClientConfig.MOCKSERVER_HOST, UUID.randomUUID()))
        );
        if (imageConfig.isMultipleSigningKeys()) {
            config.setAdditionalSigningIdentities(List.of(EnvironmentConfig.createVerifierConfig(
                    toUri(String.format(
                            "https://%s/api/v1/did/%s",
                            MockServerClientConfig.MOCKSERVER_HOST,
                            UUID.randomUUID()
                    ))
            )));
        }
        return verifierRuntimeFactory.start(new VerifierRuntimeFactory.StartRequest(
                variant,
                config,
                imageConfig,
                imageName,
                null
        ));
    }

    private void registerTp2Routes(final IssuerVariant issuerVariant, final VerifierVariant verifierVariant) {
        mockServerClientConfig.registerTp2Routes(
                mockServerClient,
                issuer(issuerVariant).config(),
                verifier(verifierVariant).config(),
                trustConfig
        );
    }

    private void ensureRunning(final String name, final GenericContainer<?> container) {
        if (!container.isRunning()) {
            throw new IllegalStateException("%s Testcontainer is not running; the shared E2E environment is invalid".formatted(name));
        }
    }

}
