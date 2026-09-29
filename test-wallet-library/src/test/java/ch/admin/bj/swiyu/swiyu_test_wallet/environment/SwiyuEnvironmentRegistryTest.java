package ch.admin.bj.swiyu.swiyu_test_wallet.environment;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.EnvironmentConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockAttestationAuthority;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.TrustConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockserver.client.MockServerClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.net.URI;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SwiyuEnvironmentRegistryTest {

    @Test
    void issuer_whenHsmVariantIsRequestedDirectly_thenStartsSoftHsmBeforeCreatingIdentity() {
        // Given
        final EnvironmentSupportServices supportServices = mock(EnvironmentSupportServices.class);
        final GenericContainer<?> softHsm = mock(GenericContainer.class);
        final AtomicBoolean softHsmStarted = new AtomicBoolean();
        when(supportServices.softHsm()).thenAnswer(invocation -> {
            softHsmStarted.set(true);
            return softHsm;
        });
        when(supportServices.tokenDirPath()).thenReturn("hsm-token-directory");

        final IssuerRuntimeFactory issuerRuntime = mock(IssuerRuntimeFactory.class);
        final IssuerHandle expectedHandle = mock(IssuerHandle.class);
        when(issuerRuntime.start(any(IssuerRuntimeFactory.StartRequest.class))).thenReturn(expectedHandle);

        final SwiyuEnvironmentRegistry registry = registry(issuerRuntime, supportServices);
        final IssuerConfig issuerConfig = mock(IssuerConfig.class);

        try (MockedStatic<EnvironmentConfig> environmentConfig = mockStatic(EnvironmentConfig.class)) {
            environmentConfig.when(() -> EnvironmentConfig.createIssuerConfig(
                            any(URI.class),
                            eq(true),
                            eq("hsm-token-directory")
                    ))
                    .thenAnswer(invocation -> {
                        assertThat(softHsmStarted)
                                .as("SoftHSM must expose its keys before HSM identity creation")
                                .isTrue();
                        return issuerConfig;
                    });

            // When
            final IssuerHandle actualHandle = registry.issuer(IssuerVariant.HSM);

            // Then
            assertThat(actualHandle).isSameAs(expectedHandle);
            verify(supportServices).softHsm();
            verify(issuerRuntime).start(any(IssuerRuntimeFactory.StartRequest.class));
        }
    }

    private static SwiyuEnvironmentRegistry registry(
            final IssuerRuntimeFactory issuerRuntime,
            final EnvironmentSupportServices supportServices) {
        return new SwiyuEnvironmentRegistry(
                mock(PostgreSQLContainer.class),
                mock(MockServerContainer.class),
                mock(MockServerClient.class),
                mock(MockServerClientConfig.class),
                mock(TrustConfig.class),
                mock(MockAttestationAuthority.class),
                new IssuerImageConfig(),
                new VerifierImageConfig(),
                issuerRuntime,
                mock(VerifierRuntimeFactory.class),
                supportServices
        );
    }
}
