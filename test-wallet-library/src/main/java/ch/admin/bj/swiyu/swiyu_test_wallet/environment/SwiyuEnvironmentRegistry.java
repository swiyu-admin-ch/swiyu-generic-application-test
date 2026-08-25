package ch.admin.bj.swiyu.swiyu_test_wallet.environment;

import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuanceService;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import org.mockserver.client.MockServerClient;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;

import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.EnumMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

public class SwiyuEnvironmentRegistry {

    private static final String KEY_ID = "test-key-1";

    private final Network network;
    private final PostgreSQLContainer<?> dbContainer;
    private final MockServerContainer mockServerContainer;
    private final MockServerClient mockServerClient;
    private final MockServerClientConfig mockServerClientConfig;
    private final TrustConfig trustConfig;
    private final MockAttestationAuthority mockAttestationAuthority;
    private final ContainerLogConfig containerLogConfig;
    private final IssuerImageConfig issuerImageTemplate;
    private final VerifierImageConfig verifierImageTemplate;
    private final ManagementAuthConfig managementAuthTemplate;
    private final HSMConfig hsmConfig;
    private final String tokenDirPath;

    private final Map<IssuerVariant, IssuerHandle> issuers = new EnumMap<>(IssuerVariant.class);
    private final Map<VerifierVariant, VerifierHandle> verifiers = new EnumMap<>(VerifierVariant.class);

    private GenericContainer<?> keycloakContainer;
    private GenericContainer<?> softHsmContainer;

    public SwiyuEnvironmentRegistry(
            final Network network,
            final PostgreSQLContainer<?> dbContainer,
            final MockServerContainer mockServerContainer,
            final MockServerClient mockServerClient,
            final MockServerClientConfig mockServerClientConfig,
            final TrustConfig trustConfig,
            final MockAttestationAuthority mockAttestationAuthority,
            final ContainerLogConfig containerLogConfig,
            final IssuerImageConfig issuerImageTemplate,
            final VerifierImageConfig verifierImageTemplate,
            final ManagementAuthConfig managementAuthTemplate,
            final HSMConfig hsmConfig,
            final String tokenDirPath) {
        this.network = network;
        this.dbContainer = dbContainer;
        this.mockServerContainer = mockServerContainer;
        this.mockServerClient = mockServerClient;
        this.mockServerClientConfig = mockServerClientConfig;
        this.trustConfig = trustConfig;
        this.mockAttestationAuthority = mockAttestationAuthority;
        this.containerLogConfig = containerLogConfig;
        this.issuerImageTemplate = issuerImageTemplate;
        this.verifierImageTemplate = verifierImageTemplate;
        this.managementAuthTemplate = managementAuthTemplate;
        this.hsmConfig = hsmConfig;
        this.tokenDirPath = tokenDirPath;
    }

    public synchronized void ensureStarted(final SwiyuEnvironmentSelection selection) {
        ensureRunning("database", dbContainer);
        ensureRunning("mockserver", mockServerContainer);
        stopUnselectedIssuers(selection.issuers());
        stopUnselectedVerifiers(selection.verifiers());
        if (selection.hsm()) {
            softHsm();
        }
        if (selection.keycloak()) {
            keycloak();
        }
        selection.issuers().forEach(this::issuer);
        selection.verifiers().forEach(this::verifier);
        registerTp2Routes(selection.primaryIssuer(), selection.primaryVerifier());
    }

    public synchronized IssuerHandle issuer(final IssuerVariant variant) {
        final IssuerHandle existingIssuer = issuers.get(variant);
        if (existingIssuer != null && !existingIssuer.container().isRunning()) {
            issuers.remove(variant);
        }
        return issuers.computeIfAbsent(variant, this::startIssuer);
    }

    public synchronized IssuerHandle refreshStatusList(final IssuerVariant variant) {
        final IssuerHandle issuer = issuer(variant);
        final StatusList statusList = createStatusList(issuer.manager(), issuer.jwtKey());
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
        final ManagementAuthConfig managementAuthConfig = managementAuth(variant.requiresKeycloak());
        final String imageName = imageConfig.getBaseImage() + ":" + imageConfig.getImageTag();

        if (variant.requiresHsm()) {
            softHsm();
        }
        if (variant.requiresKeycloak()) {
            keycloak();
        }

        final IssuerConfig config = EnvironmentConfig.createIssuerConfig(
                toUri(String.format("https://%s/api/v1/did/%s", MockServerClientConfig.MOCKSERVER_HOST, UUID.randomUUID())),
                imageConfig.isEnableHsm(),
                imageConfig.isEnableHsm() ? tokenDirPath : null
        );
        mockServerClientConfig.registerIssuer(config);

        final GenericContainer<?> container = IssuerContainerConfig.createIssuerContainer(
                network,
                dbContainer,
                config,
                mockServerContainer,
                imageName,
                imageConfig,
                managementAuthConfig,
                containerLogConfig,
                tokenDirPath,
                mockAttestationAuthority
        );
        if (imageConfig.isEnableHsm()) {
            container.dependsOn(softHsm());
        }
        if (variant.requiresKeycloak()) {
            container.dependsOn(keycloak());
        }
        container.start();

        config.setIssuerServiceUrl(serviceUrl(container));
        final BusinessIssuer manager = new BusinessIssuer(config);
        String managementAccessToken = null;
        if (variant.requiresKeycloak()) {
            managementAccessToken = clientCredentialsToken(
                    managementAuthConfig.getIssuerClientId(),
                    managementAuthConfig.getIssuerClientSecret()
            );
            manager.useBearerToken(managementAccessToken);
        }

        final PrivateKey jwtKey = imageConfig.isEnableJwtAuth() && imageConfig.getJwtKeyGenerator() != null
                ? imageConfig.getJwtKeyGenerator().getPrivateKey()
                : null;
        final PrivateKey unauthenticatedJwtKey = jwtKey == null ? null : generateUnauthenticatedJwtKey();
        manager.onStatusListCreated(statusList -> mockServerClientConfig.setCurrentStatusList(
                config.getIssuerDid(),
                String.valueOf(statusList.getStatusRegistryUrl())
        ));
        final StatusList statusList = createStatusList(manager, jwtKey);

        return new IssuerHandle(
                variant,
                config,
                imageConfig,
                container,
                manager,
                new IssuanceService(config.getIssuerServiceUrl()),
                serviceLocation(container),
                statusList,
                jwtKey,
                unauthenticatedJwtKey,
                KEY_ID,
                managementAuthConfig,
                managementAccessToken
        );
    }

    private StatusList createStatusList(final BusinessIssuer manager, final PrivateKey jwtKey) {
        return jwtKey == null
                ? manager.createStatusList(100000, 2)
                : manager.createStatusListWithSignedJwt(jwtKey, KEY_ID, 100000, 2);
    }

    private VerifierHandle startVerifier(final VerifierVariant variant) {
        final VerifierImageConfig imageConfig = variant.imageConfig(verifierImageTemplate);
        final ManagementAuthConfig managementAuthConfig = managementAuth(variant.requiresKeycloak());
        final String imageName = imageConfig.getBaseImage() + ":" + imageConfig.getImageTag();

        if (variant.requiresHsm()) {
            softHsm();
        }
        if (variant.requiresKeycloak()) {
            keycloak();
        }

        final VerifierConfig config = EnvironmentConfig.createVerifierConfig(
                toUri(String.format("https://%s/api/v1/did/%s", MockServerClientConfig.MOCKSERVER_HOST, UUID.randomUUID()))
        );
        mockServerClientConfig.registerVerifier(config);

        final GenericContainer<?> container = VerifierContainerConfig.createVerifierContainer(
                network,
                dbContainer,
                config,
                imageName,
                imageConfig,
                managementAuthConfig,
                tokenDirPath,
                containerLogConfig
        );
        if (imageConfig.isEnableHsm()) {
            container.dependsOn(softHsm());
        }
        if (variant.requiresKeycloak()) {
            container.dependsOn(keycloak());
        }
        container.start();

        final VerifierManager manager = new VerifierManager(serviceUrl(container));
        String managementAccessToken = null;
        if (variant.requiresKeycloak()) {
            managementAccessToken = clientCredentialsToken(
                    managementAuthConfig.getVerifierClientId(),
                    managementAuthConfig.getVerifierClientSecret()
            );
            manager.useBearerToken(managementAccessToken);
        }

        return new VerifierHandle(
                variant,
                config,
                imageConfig,
                container,
                manager,
                serviceLocation(container),
                managementAuthConfig,
                managementAccessToken
        );
    }

    private void registerTp2Routes(final IssuerVariant issuerVariant, final VerifierVariant verifierVariant) {
        mockServerClientConfig.registerTp2Routes(
                mockServerClient,
                issuer(issuerVariant).config(),
                verifier(verifierVariant).config(),
                trustConfig
        );
    }

    private GenericContainer<?> keycloak() {
        if (keycloakContainer == null) {
            keycloakContainer = KeycloakContainerConfig.createKeycloakContainer(network, managementAuth(true));
            keycloakContainer.start();
        }
        ensureRunning("keycloak", keycloakContainer);
        return keycloakContainer;
    }

    private GenericContainer<?> softHsm() {
        if (softHsmContainer == null) {
            softHsmContainer = HSMContainerConfig.createSoftHsmContainer(
                    network,
                    hsmConfig,
                    tokenDirPath,
                    containerLogConfig
            );
            softHsmContainer.start();
        }
        ensureRunning("softHSM", softHsmContainer);
        return softHsmContainer;
    }

    private ManagementAuthConfig managementAuth(final boolean enabled) {
        final ManagementAuthConfig config = new ManagementAuthConfig();
        config.setEnabled(enabled);
        config.setKeycloakImage(managementAuthTemplate.getKeycloakImage());
        config.setRealm(managementAuthTemplate.getRealm());
        config.setNetworkAlias(managementAuthTemplate.getNetworkAlias());
        config.setPort(managementAuthTemplate.getPort());
        config.setIssuerClientId(managementAuthTemplate.getIssuerClientId());
        config.setIssuerClientSecret(managementAuthTemplate.getIssuerClientSecret());
        config.setVerifierClientId(managementAuthTemplate.getVerifierClientId());
        config.setVerifierClientSecret(managementAuthTemplate.getVerifierClientSecret());
        config.setJwsAlgorithms(managementAuthTemplate.getJwsAlgorithms());
        return config;
    }

    private String clientCredentialsToken(final String clientId, final String clientSecret) {
        final MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "client_credentials");
        formData.add("client_id", clientId);
        formData.add("client_secret", clientSecret);

        final Map<String, Object> response = RestClient.builder().build().post()
                .uri(managementAuth(true).getHostTokenUri(keycloak()))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(formData)
                .retrieve()
                .body(Map.class);

        if (response == null || response.get("access_token") == null) {
            throw new IllegalStateException("Keycloak token endpoint did not return an access_token");
        }
        return response.get("access_token").toString();
    }

    private PrivateKey generateUnauthenticatedJwtKey() {
        try {
            final KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
            keyPairGen.initialize(new ECGenParameterSpec("secp256r1"));
            return keyPairGen.generateKeyPair().getPrivate();
        } catch (Exception e) {
            throw new IllegalStateException("Could not generate unauthenticated JWT key", e);
        }
    }

    private void ensureRunning(final String name, final GenericContainer<?> container) {
        if (!container.isRunning()) {
            throw new IllegalStateException("%s Testcontainer is not running; the shared E2E environment is invalid".formatted(name));
        }
    }

    private String serviceUrl(final GenericContainer<?> container) {
        return "http://%s:%d".formatted(container.getHost(), container.getMappedPort(8080));
    }

    private ServiceLocationContext serviceLocation(final GenericContainer<?> container) {
        return new ServiceLocationContext(container.getHost(), container.getMappedPort(8080).toString());
    }
}
