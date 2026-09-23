package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerHandle;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerRuntimeFactory;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IssuerVersionTransitionTest {

    @Test
    void startPrevious_whenStatusListIsMissing_thenRetainsPreviousForSafeCleanup() {
        final IssuerRuntimeFactory runtimeFactory = mock(IssuerRuntimeFactory.class);
        final IssuerHandle previousHandle = mock(IssuerHandle.class);
        final GenericContainer<?> previousContainer = runningContainer();
        doReturn(previousContainer).when(previousHandle).container();
        when(runtimeFactory.start(any(IssuerRuntimeFactory.StartRequest.class)))
                .thenReturn(previousHandle);

        final RegressionSchema schema = mock(RegressionSchema.class);
        final IssuerVersionTransition transition = transition(runtimeFactory, schema);

        assertThatThrownBy(transition::startPrevious)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("status list required by Candidate");

        assertThat(transition.state()).isEqualTo(TransitionState.PREVIOUS_INVALID);
        assertThatThrownBy(() -> transition.preparePrevious(handle -> "artifact"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("transition is PREVIOUS_INVALID");
        verify(previousContainer, never()).stop();
        verify(runtimeFactory, times(1)).start(any(IssuerRuntimeFactory.StartRequest.class));

        transition.close();
        transition.close();
        verify(previousContainer).stop();
        verify(schema, times(1)).remove();
    }

    @Test
    void close_whenInvalidPreviousCannotStopInitially_thenRetainsOwnershipAndRetriesBeforeRemovingSchema() {
        final IssuerRuntimeFactory runtimeFactory = mock(IssuerRuntimeFactory.class);
        final IssuerHandle previousHandle = mock(IssuerHandle.class);
        final GenericContainer<?> previousContainer = runningContainer();
        doReturn(previousContainer).when(previousHandle).container();
        when(runtimeFactory.start(any(IssuerRuntimeFactory.StartRequest.class)))
                .thenReturn(previousHandle);
        doThrow(new IllegalStateException("stop failed"))
                .doNothing()
                .when(previousContainer).stop();

        final RegressionSchema schema = mock(RegressionSchema.class);
        final IssuerVersionTransition transition = transition(runtimeFactory, schema);
        assertThatThrownBy(transition::startPrevious)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("status list required by Candidate");

        assertThatThrownBy(transition::close)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("stop failed");
        verify(schema, never()).remove();

        transition.close();

        assertThat(transition.state()).isEqualTo(TransitionState.CLOSED);
        verify(previousContainer, times(2)).stop();
        verify(schema).remove();
    }

    private static IssuerVersionTransition transition(
            final IssuerRuntimeFactory runtimeFactory,
            final RegressionSchema schema) {
        when(schema.schemaName()).thenReturn("swiyu_issuer_regression_unit");
        final MountableFile metadata = MountableFile.forClasspathResource("metadata-source/valid.json");
        return new IssuerVersionTransition(
                component("4.1.0", "previous"),
                component("4.2.0", "candidate"),
                runtimeFactory,
                IssuerConfig.builder().issuerDid("did:example:issuer").build(),
                new IssuerImageConfig(),
                new IssuerImageConfig(),
                metadata,
                metadata,
                schema
        );
    }

    private static VersionedComponent<IssuerVariant> component(
            final String version,
            final String imageId) {
        final String baseImage = "registry.example/issuer";
        return new VersionedComponent<>(
                version,
                IssuerVariant.DEFAULT,
                "classpath:metadata-source/valid.json",
                new ResolvedImage(
                        DockerImageName.parse(baseImage).withTag(version),
                        baseImage + ":" + version,
                        "sha256:" + imageId
                )
        );
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static GenericContainer<?> runningContainer() {
        final GenericContainer container = mock(GenericContainer.class);
        when(container.isRunning()).thenReturn(true);
        return container;
    }
}
