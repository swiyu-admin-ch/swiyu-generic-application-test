package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import com.github.dockerjava.api.model.Bind;
import com.github.dockerjava.api.model.Volume;
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
    public static final String TOKEN_VOLUME = "softhsm-tokens";

    private static final String INIT_SCRIPT = """
        #!/bin/sh
        set -eux

        : "${HSM_LIBRARY:?HSM_LIBRARY is required}"
        : "${HSM_TOKEN_DIR:?HSM_TOKEN_DIR is required}"
        : "${SOFTHSM2_CONF:?SOFTHSM2_CONF is required}"
        : "${HSM_TOKEN:?HSM_TOKEN is required}"
        : "${HSM_PIN:?HSM_PIN is required}"
        : "${HSM_SO_PIN:?HSM_SO_PIN is required}"
        : "${HSM_LABEL:?HSM_LABEL is required}"
        : "${HSM_SIGNING_ALGORITHM:?HSM_SIGNING_ALGORITHM is required}"

        mkdir -p "${HSM_TOKEN_DIR}"

        echo "directories.tokendir = ${HSM_TOKEN_DIR}" > "${SOFTHSM2_CONF}"
        export SOFTHSM2_CONF

        echo "Initialising token: ${HSM_TOKEN}"

        softhsm2-util \
          --init-token \
          --free \
          --label "${HSM_TOKEN}" \
          --pin "${HSM_PIN}" \
          --so-pin "${HSM_SO_PIN}"

        echo "Generating key: ${HSM_LABEL}"

        case "${HSM_SIGNING_ALGORITHM}" in
          ES256) CURVE="prime256v1" ;;
          ES384) CURVE="secp384r1" ;;
          ES512) CURVE="secp521r1" ;;
          *)
            echo "Unsupported HSM_SIGNING_ALGORITHM: ${HSM_SIGNING_ALGORITHM}"
            exit 1
            ;;
        esac

        pkcs11-tool \
          --module "${HSM_LIBRARY}" \
          --login \
          --pin "${HSM_PIN}" \
          --token-label "${HSM_TOKEN}" \
          --keypairgen \
          --key-type "EC:${CURVE}" \
          --label "${HSM_LABEL}" \
          --usage-sign

        echo "Listing objects"

        pkcs11-tool \
          --module "${HSM_LIBRARY}" \
          --login \
          --pin "${HSM_PIN}" \
          --token-label "${HSM_TOKEN}" \
          --list-objects

        echo "HSM container initialised successfully"

        sleep infinity
        """;

    private static final String DOCKERFILE = """
        FROM alpine:3.19
        RUN apk add --no-cache softhsm opensc
        COPY init-hsm.sh /usr/local/bin/init-hsm.sh
        RUN chmod +x /usr/local/bin/init-hsm.sh
        ENTRYPOINT ["/usr/local/bin/init-hsm.sh"]
        """;

    @SuppressWarnings("java:S1452")
    public static GenericContainer<?> createSoftHsmContainer(
            final Network network,
            final SoftHsmImageConfig hsmConfig) {

        final ImageFromDockerfile image = new ImageFromDockerfile("softhsm2-testcontainer", true)
                .withFileFromString("Dockerfile", DOCKERFILE)
                .withFileFromString("init-hsm.sh", INIT_SCRIPT);

        GenericContainer<?> container = new GenericContainer<>(image)
                .withNetwork(network)
                .withNetworkAliases(hsmConfig.getNetworkAlias())
                .withEnv("HSM_LIBRARY", LIB_SOFTHSM2_SO)
                .withEnv("HSM_TOKEN_DIR", TOKEN_DIR)
                .withEnv("SOFTHSM2_CONF", SOFTHSM2_CONF_PATH)
                .withEnv("HSM_TOKEN", hsmConfig.getTokenLabel())
                .withEnv("HSM_PIN", hsmConfig.getPin())
                .withEnv("HSM_SO_PIN", hsmConfig.getSoPin())
                .withEnv("HSM_LABEL", hsmConfig.getKeyLabel())
                .withEnv("HSM_SIGNING_ALGORITHM", hsmConfig.getSigningAlgorithm())
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("SoftHsmContainer")))
                .withCreateContainerCmdModifier(cmd ->
                        cmd.getHostConfig().withBinds(
                                new Bind(TOKEN_VOLUME, new Volume(TOKEN_DIR))
                        )
                )
                .waitingFor(
                        Wait.forLogMessage(".*HSM container initialised successfully.*", 1)
                                .withStartupTimeout(Duration.ofSeconds(30))
                );

        return container;
    }
}