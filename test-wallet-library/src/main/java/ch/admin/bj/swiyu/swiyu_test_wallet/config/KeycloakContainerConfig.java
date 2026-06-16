package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.experimental.UtilityClass;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.DockerImageName;

@UtilityClass
public class KeycloakContainerConfig {

    @SuppressWarnings("java:S1452") // Testcontainers API requires wildcard return type here
    public static GenericContainer<?> createKeycloakContainer(
            Network network,
            ManagementAuthConfig managementAuthConfig) {

        return new GenericContainer<>(DockerImageName.parse(managementAuthConfig.getKeycloakImage()))
                .withEnv("KEYCLOAK_ADMIN", "admin")
                .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
                .withNetwork(network)
                .withNetworkAliases(managementAuthConfig.getNetworkAlias())
                .withExposedPorts(managementAuthConfig.getPort())
                .withCopyToContainer(
                        Transferable.of(managementAuthConfig.getRealmJson()),
                        "/opt/keycloak/data/import/realm-%s.json".formatted(managementAuthConfig.getRealm())
                )
                .withCommand(
                        "start-dev",
                        "--http-port=%d".formatted(managementAuthConfig.getPort()),
                        "--hostname=%s".formatted(managementAuthConfig.getContainerBaseUri()),
                        "--hostname-strict=true",
                        "--import-realm"
                )
                .waitingFor(Wait.forHttp("/realms/" + managementAuthConfig.getRealm())
                        .forPort(managementAuthConfig.getPort())
                        .forStatusCode(200));
    }
}
