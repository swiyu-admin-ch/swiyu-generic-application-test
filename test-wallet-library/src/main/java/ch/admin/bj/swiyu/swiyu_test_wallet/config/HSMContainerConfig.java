package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.experimental.UtilityClass;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;


@UtilityClass
public class HSMContainerConfig {

    public static final String IMAGE_NAME = "eclipse-temurin:21-jre-ubi9-minimal";

    public static GenericContainer<?> createSoftHsmContainer(
            final Network network,
            final HSMConfig hsmConfig,
            final String tokenDirPath) {

        GenericContainer<?> container = new GenericContainer<>(IMAGE_NAME)
                .withNetwork(network)
                .withNetworkAliases(hsmConfig.getNetworkAlias());

        container
                .withEnv("SIGNING_KEY_MANAGEMENT_METHOD", HSMConfig.SIGNING_KEY_METHOD)
                .withEnv("HSM_USER", hsmConfig.getHsmUser())
                .withEnv("HSM_PASSWORD", hsmConfig.getHsmPassword())
                .withEnv("HSM_USER_PIN", hsmConfig.getHsmUserPin())
                .withEnv("HSM_LABEL", hsmConfig.getHsmKeyId())
                .withEnv("HSM_KEY_ID", hsmConfig.getHsmKeyId())
                .withEnv("HSM_KEY_PIN", hsmConfig.getHsmKeyPin())
                .withEnv("HSM_STATUS_KEY_ID", hsmConfig.getHsmStatusKeyId())
                .withEnv("HSM_STATUS_KEY_PIN", hsmConfig.getHsmStatusKeyPin())
                .withEnv("HSM_CONFIG_PATH", HSMConfig.PKCS11_CFG)
                .withEnv("SOFTHSM2_CONF", HSMConfig.SOFTHSM_CONF)
                .withEnv("HSM_TOKEN_DIR", HSMConfig.TOKEN_DIR)
                .withEnv("HSM_LIBRARY", HSMConfig.LIB_PATH)
                .withEnv("HSM_CONFIG_PATH", HSMConfig.PKCS11_CFG)
                .withEnv("KEYS_DIR", HSMConfig.KEYS_DIR)
                .withEnv("STATUS_LIST_KEY", "")
                .withEnv("SDJWT_KEY", "");

        HSMConfig.FILES.forEach(file ->
                container.withCopyFileToContainer(
                        MountableFile.forClasspathResource((String) file[0], (int) file[2]),
                        (String) file[1]
                )
        );

        container.withCopyFileToContainer(MountableFile.forClasspathResource("softhsm/keys", 0755)
                ,  "/opt/keys");

        container
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("SoftHsmContainer")))
                .withFileSystemBind(tokenDirPath, HSMConfig.TOKEN_DIR, BindMode.READ_WRITE)
                .withCommand("/bin/sh", "-c", "bash " + HSMConfig.INIT_SCRIPT + " && tail -f /dev/null")
                .waitingFor(
                        Wait.forLogMessage(".*HSM container initialised successfully.*", 1)
                                .withStartupTimeout(Duration.ofSeconds(30))
                );

        return container;
    }
}
