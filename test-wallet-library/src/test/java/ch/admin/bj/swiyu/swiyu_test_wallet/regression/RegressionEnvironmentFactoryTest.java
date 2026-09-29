package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.EnvironmentConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.RegressionProperties;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerHandle;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerRuntimeFactory;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierHandle;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierRuntimeFactory;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Verifies the cross-component contract of the public regression-environment façade. */
@SuppressWarnings({"PMD.ExcessiveImports", "PMD.CouplingBetweenObjects"})
class RegressionEnvironmentFactoryTest {

    private static final String ISSUER_IMAGE = "registry.example/issuer";
    private static final String VERIFIER_IMAGE = "registry.example/verifier";
    private static final String PREVIOUS_VERSION = "4.1.0";
    private static final String CANDIDATE_VERSION = "4.2.0";
    private static final String RESOLVED_SUFFIX = "-resolved";

    @TempDir
    Path temporaryDirectory;

    @Test
    void issuerTransition_mapsBothSidesAndReusesIdentitySchemaAndStatusListWithoutResolvingVerifier()
            throws IOException {
        final String previousMetadata = "classpath:metadata-source/valid.json";
        final String candidateMetadata = createMetadataFile("issuer-candidate.json");
        final RegressionProperties properties = issuerProperties(previousMetadata, candidateMetadata);
        properties.getVerifier().getPrevious().setVariant("HSM");

        final IssuerRuntimeFactory issuerRuntime = mock(IssuerRuntimeFactory.class);
        final VerifierRuntimeFactory verifierRuntime = mock(VerifierRuntimeFactory.class);
        final RegressionImageResolver imageResolver = mock(RegressionImageResolver.class);
        when(imageResolver.resolvePair("issuer", ISSUER_IMAGE, versions()))
                .thenReturn(images(ISSUER_IMAGE, PREVIOUS_VERSION, CANDIDATE_VERSION));

        final StatusList previousStatusList = new StatusList();
        final GenericContainer<?> previousContainer = runningContainer();
        final IssuerHandle previousHandle = mock(IssuerHandle.class);
        doReturn(previousContainer).when(previousHandle).container();
        when(previousHandle.statusList()).thenReturn(previousStatusList);
        final IssuerHandle candidateHandle = mock(IssuerHandle.class);
        when(issuerRuntime.start(any(IssuerRuntimeFactory.StartRequest.class)))
                .thenReturn(previousHandle, candidateHandle);

        final RegressionEnvironmentFactory factory = factory(
                properties,
                issuerRuntime,
                verifierRuntime,
                imageResolver
        );

        final IssuerConfig logicalConfig = IssuerConfig.builder()
                .issuerDid("did:tdw:issuer-regression")
                .issuerAssertKeyId("did:tdw:issuer-regression#assert-key-01")
                .build();
        final IssuerVersionTransition transition;
        try (MockedStatic<EnvironmentConfig> environmentConfig = mockStatic(EnvironmentConfig.class)) {
            environmentConfig.when(() -> EnvironmentConfig.createIssuerConfig(
                            any(URI.class), eq(false), eq(null)))
                    .thenReturn(logicalConfig);
            transition = factory.issuerTransition();
        }
        assertThat(transition.startPrevious()).isSameAs(previousHandle);
        final IssuerHandle preparedPrevious = transition.preparePrevious(handle -> handle);
        assertThat(preparedPrevious).isSameAs(previousHandle);
        assertThat(transition.upgradeToCandidate()).isSameAs(candidateHandle);

        final ArgumentCaptor<IssuerRuntimeFactory.StartRequest> requests =
                ArgumentCaptor.forClass(IssuerRuntimeFactory.StartRequest.class);
        verify(issuerRuntime, times(2)).start(requests.capture());
        final List<IssuerRuntimeFactory.StartRequest> captured = requests.getAllValues();
        final IssuerRuntimeFactory.StartRequest previous = captured.get(0);
        final IssuerRuntimeFactory.StartRequest candidate = captured.get(1);

        assertThat(previous.variant()).isEqualTo(IssuerVariant.DEFAULT);
        assertThat(candidate.variant()).isEqualTo(IssuerVariant.SIGNED_METADATA);
        assertThat(previous.imageConfig().getImageTag()).isEqualTo(PREVIOUS_VERSION);
        assertThat(candidate.imageConfig().getImageTag()).isEqualTo(CANDIDATE_VERSION);
        assertThat(previous.imageName()).isEqualTo(ISSUER_IMAGE + ":" + PREVIOUS_VERSION + RESOLVED_SUFFIX);
        assertThat(candidate.imageName()).isEqualTo(ISSUER_IMAGE + ":" + CANDIDATE_VERSION + RESOLVED_SUFFIX);
        assertThat(previous.metadata().getFilesystemPath()).endsWith("metadata-source/valid.json");
        assertThat(candidate.metadata().getFilesystemPath())
                .endsWith("issuer-candidate.json");
        assertThat(transition.previous().version()).isEqualTo(PREVIOUS_VERSION);
        assertThat(transition.candidate().version()).isEqualTo(CANDIDATE_VERSION);
        assertThat(transition.previous().metadata()).isEqualTo(previousMetadata);
        assertThat(transition.candidate().metadata()).isEqualTo(candidateMetadata);
        assertThat(transition.previous().image().imageId()).isEqualTo("sha256:previous");
        assertThat(transition.candidate().image().imageId()).isEqualTo("sha256:candidate");

        assertThat(previous.config()).isSameAs(candidate.config());
        assertThat(previous.config().getIssuerDid()).isNotBlank();
        assertThat(previous.config().getIssuerAssertKeyId()).isEqualTo(candidate.config().getIssuerAssertKeyId());
        assertThat(previous.imageConfig().getDbSchema())
                .isEqualTo(candidate.imageConfig().getDbSchema())
                .isEqualTo(transition.schemaName());
        assertThat(previous.imageConfig().isSignedMetadata()).isFalse();
        assertThat(candidate.imageConfig().isSignedMetadata()).isTrue();
        assertThat(previous.existingStatusList()).isNull();
        assertThat(candidate.existingStatusList()).isSameAs(previousStatusList);

        verify(previousContainer).stop();
        verify(imageResolver, never()).resolvePair(
                eq("verifier"), anyString(), any(RegressionImageResolver.RequestedVersions.class));
        verifyNoInteractions(verifierRuntime);
    }

    @Test
    void verifierTransition_mapsBothSidesAndReusesIdentityAndSchemaWithoutResolvingIssuer()
            throws IOException {
        final String previousMetadata = "classpath:metadata-source/valid.json";
        final String candidateMetadata = createMetadataFile("verifier-candidate.json");
        final RegressionProperties properties = verifierProperties(previousMetadata, candidateMetadata);
        properties.getIssuer().getPrevious().setVariant("HSM");

        final IssuerRuntimeFactory issuerRuntime = mock(IssuerRuntimeFactory.class);
        final VerifierRuntimeFactory verifierRuntime = mock(VerifierRuntimeFactory.class);
        final RegressionImageResolver imageResolver = mock(RegressionImageResolver.class);
        when(imageResolver.resolvePair("verifier", VERIFIER_IMAGE, versions()))
                .thenReturn(images(VERIFIER_IMAGE, PREVIOUS_VERSION, CANDIDATE_VERSION));

        final GenericContainer<?> previousContainer = runningContainer();
        final VerifierHandle previousHandle = mock(VerifierHandle.class);
        doReturn(previousContainer).when(previousHandle).container();
        final VerifierHandle candidateHandle = mock(VerifierHandle.class);
        when(verifierRuntime.start(any(VerifierRuntimeFactory.StartRequest.class)))
                .thenReturn(previousHandle, candidateHandle);

        final RegressionEnvironmentFactory factory = factory(
                properties,
                issuerRuntime,
                verifierRuntime,
                imageResolver
        );

        final VerifierConfig logicalConfig = VerifierConfig.builder()
                .verifierDid("did:tdw:verifier-regression")
                .verifierAuthKeyId("did:tdw:verifier-regression#auth-key-01")
                .build();
        final VerifierVersionTransition transition;
        try (MockedStatic<EnvironmentConfig> environmentConfig = mockStatic(EnvironmentConfig.class)) {
            environmentConfig.when(() -> EnvironmentConfig.createVerifierConfig(any(URI.class)))
                    .thenReturn(logicalConfig);
            transition = factory.verifierTransition();
        }
        assertThat(transition.startPrevious()).isSameAs(previousHandle);
        final VerifierHandle preparedPrevious = transition.preparePrevious(handle -> handle);
        assertThat(preparedPrevious).isSameAs(previousHandle);
        assertThat(transition.upgradeToCandidate()).isSameAs(candidateHandle);

        final ArgumentCaptor<VerifierRuntimeFactory.StartRequest> requests =
                ArgumentCaptor.forClass(VerifierRuntimeFactory.StartRequest.class);
        verify(verifierRuntime, times(2)).start(requests.capture());
        final List<VerifierRuntimeFactory.StartRequest> captured = requests.getAllValues();
        final VerifierRuntimeFactory.StartRequest previous = captured.get(0);
        final VerifierRuntimeFactory.StartRequest candidate = captured.get(1);

        assertThat(previous.variant()).isEqualTo(VerifierVariant.DEFAULT);
        assertThat(candidate.variant()).isEqualTo(VerifierVariant.SHORT_LIVED_REQUEST_OBJECT);
        assertThat(previous.imageConfig().getImageTag()).isEqualTo(PREVIOUS_VERSION);
        assertThat(candidate.imageConfig().getImageTag()).isEqualTo(CANDIDATE_VERSION);
        assertThat(previous.imageName()).isEqualTo(VERIFIER_IMAGE + ":" + PREVIOUS_VERSION + RESOLVED_SUFFIX);
        assertThat(candidate.imageName()).isEqualTo(VERIFIER_IMAGE + ":" + CANDIDATE_VERSION + RESOLVED_SUFFIX);
        assertThat(previous.metadata().getFilesystemPath()).endsWith("metadata-source/valid.json");
        assertThat(candidate.metadata().getFilesystemPath())
                .endsWith("verifier-candidate.json");
        assertThat(transition.previous().version()).isEqualTo(PREVIOUS_VERSION);
        assertThat(transition.candidate().version()).isEqualTo(CANDIDATE_VERSION);
        assertThat(transition.previous().metadata()).isEqualTo(previousMetadata);
        assertThat(transition.candidate().metadata()).isEqualTo(candidateMetadata);
        assertThat(transition.previous().image().imageId()).isEqualTo("sha256:previous");
        assertThat(transition.candidate().image().imageId()).isEqualTo("sha256:candidate");

        assertThat(previous.config()).isSameAs(candidate.config());
        assertThat(previous.config().getVerifierDid()).isNotBlank();
        assertThat(previous.config().getVerifierAuthKeyId()).isEqualTo(candidate.config().getVerifierAuthKeyId());
        assertThat(previous.imageConfig().getDbSchema())
                .isEqualTo(candidate.imageConfig().getDbSchema())
                .isEqualTo(transition.schemaName());
        assertThat(previous.imageConfig().getRequestObjectTtlSeconds()).isZero();
        assertThat(candidate.imageConfig().getRequestObjectTtlSeconds()).isPositive();

        verify(previousContainer).stop();
        verify(imageResolver, never()).resolvePair(
                eq("issuer"), anyString(), any(RegressionImageResolver.RequestedVersions.class));
        verifyNoInteractions(issuerRuntime);
    }

    private RegressionEnvironmentFactory factory(
            final RegressionProperties properties,
            final IssuerRuntimeFactory issuerRuntime,
            final VerifierRuntimeFactory verifierRuntime,
            final RegressionImageResolver imageResolver) {
        final IssuerImageConfig issuerImage = new IssuerImageConfig();
        issuerImage.setBaseImage(ISSUER_IMAGE);
        final VerifierImageConfig verifierImage = new VerifierImageConfig();
        verifierImage.setBaseImage(VERIFIER_IMAGE);
        return new RegressionEnvironmentFactory(
                properties,
                issuerImage,
                verifierImage,
                issuerRuntime,
                verifierRuntime,
                mock(PostgreSQLContainer.class),
                imageResolver
        );
    }

    private static RegressionProperties issuerProperties(
            final String previousMetadata,
            final String candidateMetadata) {
        final RegressionProperties properties = new RegressionProperties();
        properties.getIssuer().getPrevious().setVersion(PREVIOUS_VERSION);
        properties.getIssuer().getPrevious().setVariant("DEFAULT");
        properties.getIssuer().getPrevious().setMetadata(previousMetadata);
        properties.getIssuer().getCandidate().setVersion(CANDIDATE_VERSION);
        properties.getIssuer().getCandidate().setVariant("SIGNED_METADATA");
        properties.getIssuer().getCandidate().setMetadata(candidateMetadata);
        return properties;
    }

    private static RegressionProperties verifierProperties(
            final String previousMetadata,
            final String candidateMetadata) {
        final RegressionProperties properties = new RegressionProperties();
        properties.getVerifier().getPrevious().setVersion(PREVIOUS_VERSION);
        properties.getVerifier().getPrevious().setVariant("DEFAULT");
        properties.getVerifier().getPrevious().setMetadata(previousMetadata);
        properties.getVerifier().getCandidate().setVersion(CANDIDATE_VERSION);
        properties.getVerifier().getCandidate().setVariant("SHORT_LIVED_REQUEST_OBJECT");
        properties.getVerifier().getCandidate().setMetadata(candidateMetadata);
        return properties;
    }

    private String createMetadataFile(final String filename) throws IOException {
        final Path metadata = temporaryDirectory.resolve(filename);
        Files.writeString(metadata, "{\"credential_configurations_supported\":{}}");
        return metadata.toUri().toString();
    }

    private static RegressionImageResolver.ResolvedPair images(
            final String baseImage,
            final String previousVersion,
            final String candidateVersion) {
        return new RegressionImageResolver.ResolvedPair(
                image(baseImage, previousVersion, "previous"),
                image(baseImage, candidateVersion, "candidate")
        );
    }

    private static RegressionImageResolver.RequestedVersions versions() {
        return new RegressionImageResolver.RequestedVersions(PREVIOUS_VERSION, CANDIDATE_VERSION);
    }

    private static ResolvedImage image(
            final String baseImage,
            final String version,
            final String id) {
        return new ResolvedImage(
                DockerImageName.parse(baseImage).withTag(version),
                baseImage + ":" + version + RESOLVED_SUFFIX,
                "sha256:" + id
        );
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static GenericContainer<?> runningContainer() {
        final GenericContainer container = mock(GenericContainer.class);
        when(container.isRunning()).thenReturn(true);
        return container;
    }
}
