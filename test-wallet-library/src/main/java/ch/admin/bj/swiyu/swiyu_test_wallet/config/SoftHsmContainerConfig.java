package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.experimental.UtilityClass;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;

import java.time.Duration;

@UtilityClass
public class SoftHsmContainerConfig {

    public static final String LIB_SOFTHSM2_SO = "/usr/lib/softhsm/libsofthsm2.so";
    public static final String SOFTHSM2_CONF_PATH = "/etc/softhsm2.conf";
    public static final String TOKEN_DIR = "/var/lib/softhsm/tokens";

    private static final String INIT_SCRIPT = """
            #!/bin/sh
            set -e

            echo "==> Creating SoftHSM2 token directory"
            mkdir -p %s

            echo "==> Writing softhsm2.conf"
            cat > %s <<'EOF'
            directories.tokendir = %s
            EOF

            echo "==> Initialising token: ${HSM_TOKEN}"
            softhsm2-util --init-token --free \\
                --label "${HSM_TOKEN}" \\
                --pin "${HSM_PIN}" \\
                --so-pin "${HSM_SO_PIN}"

            # Determine the EC curve for the requested signing algorithm
            case "${HSM_SIGNING_ALGORITHM}" in
              ES256) CURVE="prime256v1" ;;
              ES384) CURVE="secp384r1"  ;;
              ES512) CURVE="secp521r1"  ;;
              *)     CURVE="prime256v1" ;;
            esac

            echo "==> Generating EC key pair (curve=${CURVE}, label=${HSM_LABEL})"
            pkcs11-tool \\
                --module %s \\
                --login --pin "${HSM_PIN}" \\
                --token-label "${HSM_TOKEN}" \\
                --keypairgen \\
                --key-type "EC:${CURVE}" \\
                --label "${HSM_LABEL}" \\
                --usage-sign

            echo "==> SoftHSM2 ready — listing objects"
            pkcs11-tool \\
                --module %s \\
                --login --pin "${HSM_PIN}" \\
                --token-label "${HSM_TOKEN}" \\
                --list-objects

            echo "==> HSM container initialised successfully"

            # Keep the container alive
            tail -f /dev/null
            """.formatted(TOKEN_DIR, SOFTHSM2_CONF_PATH, TOKEN_DIR,
            LIB_SOFTHSM2_SO, LIB_SOFTHSM2_SO);

    private static final String DOCKERFILE = """
            FROM alpine:3.19

            # softhsm  => libsofthsm2.so + softhsm2-util
            # opensc   => pkcs11-tool
            RUN apk add --no-cache softhsm opensc

            # Embed the init script
            COPY init-hsm.sh /usr/local/bin/init-hsm.sh
            RUN chmod +x /usr/local/bin/init-hsm.sh

            ENTRYPOINT ["/usr/local/bin/init-hsm.sh"]
            """;

    @SuppressWarnings("java:S1452")
    public static GenericContainer<?> createSoftHsmContainer(
            final Network network,
            final SoftHsmImageConfig hsmConfig) {

        ImageFromDockerfile image = new ImageFromDockerfile("softhsm2-testcontainer", /* deleteOnExit= */ true)
                .withFileFromString("Dockerfile", DOCKERFILE)
                .withFileFromString("init-hsm.sh", INIT_SCRIPT);

        @SuppressWarnings("resource")
        GenericContainer<?> container = new GenericContainer<>(image)
                .withNetwork(network)
                .withNetworkAliases(hsmConfig.getNetworkAlias())
                .withEnv("SOFTHSM2_CONF", SOFTHSM2_CONF_PATH)
                .withEnv("HSM_LIBRARY", LIB_SOFTHSM2_SO)
                .withEnv("HSM_TOKEN", hsmConfig.getTokenLabel())
                .withEnv("HSM_PIN", hsmConfig.getPin())
                .withEnv("HSM_SO_PIN", hsmConfig.getSoPin())
                .withEnv("HSM_LABEL", hsmConfig.getKeyLabel())
                .withEnv("HSM_SIGNING_ALGORITHM", hsmConfig.getSigningAlgorithm())
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("SoftHsmContainer")))
                .waitingFor(
                        Wait.forLogMessage(".*HSM container initialised successfully.*", 1)
                                .withStartupTimeout(Duration.ofSeconds(60)));

        return container;
    }
}

