package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.testcontainers.containers.GenericContainer;

@Component
@Getter
@Setter
@ConfigurationProperties("application.management-auth")
public class ManagementAuthConfig {

    private boolean enabled = false;
    private String keycloakImage = "quay.io/keycloak/keycloak:25.0";
    private String realm = "trust";
    private String networkAlias = "keycloak";
    private int port = 8080;
    private String issuerClientId = "issuer-client";
    private String issuerClientSecret = "Pa$$w0rd";
    private String verifierClientId = "verifier-client";
    private String verifierClientSecret = "Pa$$w0rd";
    private String jwsAlgorithms = "RS256";

    public String getContainerBaseUri() {
        return "http://%s:%d".formatted(networkAlias, port);
    }

    public String getContainerIssuerUri() {
        return "%s/realms/%s".formatted(getContainerBaseUri(), realm);
    }

    public String getContainerJwkSetUri() {
        return getContainerIssuerUri() + "/protocol/openid-connect/certs";
    }

    public String getHostTokenUri(GenericContainer<?> keycloakContainer) {
        return "http://%s:%d/realms/%s/protocol/openid-connect/token".formatted(
                keycloakContainer.getHost(),
                keycloakContainer.getMappedPort(port),
                realm
        );
    }

    public String getRealmJson() {
        return """
                {
                  "realm": "%s",
                  "enabled": true,
                  "sslRequired": "NONE",
                  "clients": [
                    {
                      "clientId": "%s",
                      "enabled": true,
                      "protocol": "openid-connect",
                      "publicClient": false,
                      "secret": "%s",
                      "serviceAccountsEnabled": true,
                      "standardFlowEnabled": false,
                      "directAccessGrantsEnabled": false,
                      "redirectUris": ["*"]
                    },
                    {
                      "clientId": "%s",
                      "enabled": true,
                      "protocol": "openid-connect",
                      "publicClient": false,
                      "secret": "%s",
                      "serviceAccountsEnabled": true,
                      "standardFlowEnabled": false,
                      "directAccessGrantsEnabled": false,
                      "redirectUris": ["*"]
                    }
                  ]
                }
                """.formatted(
                realm,
                issuerClientId,
                issuerClientSecret,
                verifierClientId,
                verifierClientSecret
        );
    }
}
