package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierHandle;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierRuntimeFactory;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class VerifierVersionTransitionTest {

    @Test
    void transition_whenPreviousIsPrepared_thenStartsCandidateAndCleansUpOwnedResources() {
        // Given a Verifier transition with distinct Previous and Candidate runtimes
        final VerifierRuntimeFactory runtimeFactory = mock(VerifierRuntimeFactory.class);
        final VerifierHandle previousHandle = mock(VerifierHandle.class);
        final VerifierHandle candidateHandle = mock(VerifierHandle.class);
        final GenericContainer<?> previousContainer = runningContainer();
        final GenericContainer<?> candidateContainer = runningContainer();
        doReturn(previousContainer).when(previousHandle).container();
        doReturn(candidateContainer).when(candidateHandle).container();
        when(runtimeFactory.start(any(VerifierRuntimeFactory.StartRequest.class)))
                .thenReturn(previousHandle, candidateHandle);

        final RegressionSchema schema = mock(RegressionSchema.class);
        when(schema.schemaName()).thenReturn("swiyu_verifier_regression_unit");
        final VerifierVersionTransition transition = transition(runtimeFactory, schema);

        // When Previous is prepared and replaced by Candidate
        final VerifierHandle currentPrevious = transition.startPrevious();
        final VerifierHandle preparedPrevious = transition.preparePrevious(current -> current);
        final VerifierHandle currentCandidate = transition.upgradeToCandidate();
        transition.close();
        transition.close();

        // Then the transition preserves its order and releases each owned resource once
        assertThat(currentPrevious).isSameAs(previousHandle);
        assertThat(preparedPrevious).isSameAs(previousHandle);
        assertThat(currentCandidate).isSameAs(candidateHandle);
        assertThat(transition.state()).isEqualTo(TransitionState.CLOSED);

        final InOrder lifecycleOrder = inOrder(runtimeFactory, previousContainer, candidateContainer, schema);
        lifecycleOrder.verify(runtimeFactory).start(any(VerifierRuntimeFactory.StartRequest.class));
        lifecycleOrder.verify(previousContainer).stop();
        lifecycleOrder.verify(runtimeFactory).start(any(VerifierRuntimeFactory.StartRequest.class));
        lifecycleOrder.verify(candidateContainer).stop();
        lifecycleOrder.verify(schema).remove();
    }

    private static VerifierVersionTransition transition(
            final VerifierRuntimeFactory runtimeFactory,
            final RegressionSchema schema) {
        final MountableFile metadata = MountableFile.forClasspathResource("metadata-source/valid.json");
        return new VerifierVersionTransition(
                component("4.1.0", "previous"),
                component("4.2.0", "candidate"),
                runtimeFactory,
                VerifierConfig.builder().verifierDid("did:example:verifier").build(),
                new VerifierImageConfig(),
                new VerifierImageConfig(),
                metadata,
                metadata,
                schema
        );
    }

    private static VersionedComponent<VerifierVariant> component(
            final String version,
            final String imageId) {
        final String baseImage = "registry.example/verifier";
        return new VersionedComponent<>(
                version,
                VerifierVariant.DEFAULT,
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
