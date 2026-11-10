package ch.admin.bj.swiyu.swiyu_test_wallet.environment;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.ContainerLogConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerContainerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ManagementAuthConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockAttestationAuthority;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ContainerUtil;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

class IssuerRenewalPolicyVariantTest {

    @TempDir
    Path resourceDirectory;

    @ParameterizedTest(name = "{0}: ENABLE_SUSPENDED_RENEWAL={1}")
    @MethodSource("renewalPolicies")
    void renewalPolicy_whenContainerIsCreated_thenExplicitPolicyDoesNotLeakToOtherIssuers(
            final IssuerVariant variant,
            final String expectedEnvironmentValue) throws IOException {
        // Given: even a permissive template must not override the default or strict test case.
        final var template = new IssuerImageConfig();
        template.setEnableSuspendedRenewal(true);
        final var imageConfig = variant.imageConfig(template);
        final var database = mock(PostgreSQLContainer.class);
        when(database.getDatabaseName()).thenReturn("swiyu_db");
        final var attestationAuthority = mock(MockAttestationAuthority.class);
        when(attestationAuthority.getDid()).thenReturn("did:example:attestation");
        final var issuerConfig = IssuerConfig.builder()
                .issuerDid("did:example:issuer")
                .issuerAssertKeyId("did:example:issuer#assert")
                .issuerAuthKeyId("did:example:issuer#auth")
                .issuerAssertKeyPemString("unused-without-starting-container")
                .issuerAuthKeyPemString("unused-without-starting-container")
                .mockServerUri("http://mockserver:1080")
                .swiyuPartnerId("test-partner")
                .build();

        // The mounted files are not read: this test builds a container without starting it.
        final Path mountedFixture = Files.writeString(resourceDirectory.resolve("fixture"), "{}");
        try (MockedStatic<ContainerUtil> resources = mockStatic(ContainerUtil.class)) {
            resources.when(() -> ContainerUtil.getResourcePath(anyString())).thenReturn(mountedFixture);
            // When
            try (var container = IssuerContainerConfig.createIssuerContainer(
                    mock(Network.class), database, issuerConfig, mock(MockServerContainer.class),
                    "swiyu-issuer:renewal-policy-test", imageConfig, new ManagementAuthConfig(),
                    new ContainerLogConfig(), null, attestationAuthority)) {
                // Then
                if (expectedEnvironmentValue == null) {
                    assertThat(container.getEnvMap())
                            .doesNotContainKey("ENABLE_SUSPENDED_RENEWAL");
                } else {
                    assertThat(container.getEnvMap())
                            .containsEntry("ENABLE_SUSPENDED_RENEWAL", expectedEnvironmentValue);
                }
                assertThat(container.getEnvMap())
                        .containsEntry("APPLICATION_DPOP_ENFORCE", "true")
                        .containsEntry("APPLICATION_ENCRYPTION_ENFORCE", "true")
                        .containsEntry("ENABLE_SIGNED_METADATA", "true");
            }
        }
        assertThat(template.getEnableSuspendedRenewal())
                .isTrue();
        assertThat(IssuerVariant.COMPLETE.imageConfig(template).getEnableSuspendedRenewal())
                .as("Selecting a renewal policy must not mutate another Issuer's template")
                .isTrue();
        assertThat(imageConfig.getDbSchema())
                .isNotEqualTo(IssuerVariant.COMPLETE.imageConfig(template).getDbSchema());
    }

    private static Stream<Arguments> renewalPolicies() {
        return Stream.of(
                Arguments.of(IssuerVariant.RENEWAL_DEFAULT, null),
                Arguments.of(IssuerVariant.RENEWAL_STRICT, "false"),
                Arguments.of(IssuerVariant.RENEWAL_PERMISSIVE_EXPERIMENTAL, "true"));
    }
}
