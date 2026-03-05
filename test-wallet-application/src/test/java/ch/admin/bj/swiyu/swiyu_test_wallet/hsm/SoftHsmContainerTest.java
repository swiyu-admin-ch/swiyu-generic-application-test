package ch.admin.bj.swiyu.swiyu_test_wallet.hsm;

import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SoftHsmContainerConfig;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.testcontainers.containers.Container.ExecResult;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class SoftHsmContainerTest extends BaseTest {

    @Test
    void softHsmToken_isInitialised_andKeyPairIsListed() throws Exception {
        String pin   = softHsmContainer.getEnvMap().get("HSM_PIN");
        String token = softHsmContainer.getEnvMap().get("HSM_TOKEN");
        String label = softHsmContainer.getEnvMap().get("HSM_LABEL");

        ExecResult result = softHsmContainer.execInContainer(
                "pkcs11-tool",
                "--module", SoftHsmContainerConfig.LIB_SOFTHSM2_SO,
                "--login", "--pin", pin,
                "--token-label", token,
                "--list-objects"
        );

        log.info("pkcs11-tool --list-objects stdout:\n{}", result.getStdout());
        if (!result.getStderr().isBlank()) {
            log.warn("pkcs11-tool --list-objects stderr:\n{}", result.getStderr());
        }

        assertThat(result.getExitCode())
                .as("pkcs11-tool --list-objects should exit 0")
                .isZero();
        assertThat(result.getStdout())
                .as("Output should contain the key label '%s'", label)
                .contains(label);
        assertThat(result.getStdout())
                .as("Output should list a Public Key Object")
                .containsIgnoringCase("Public Key Object");
        assertThat(result.getStdout())
                .as("Output should list a Private Key Object")
                .containsIgnoringCase("Private Key Object");
    }

    @Test
    void softHsm_signing_producesNonEmptySignature() throws Exception {
        String pin    = softHsmContainer.getEnvMap().get("HSM_PIN");
        String token  = softHsmContainer.getEnvMap().get("HSM_TOKEN");
        String label  = softHsmContainer.getEnvMap().get("HSM_LABEL");

        ExecResult writePayload = softHsmContainer.execInContainer(
                "sh", "-c", "echo -n 'hello-hsm' > /tmp/payload.bin"
        );
        assertThat(writePayload.getExitCode()).as("writing payload").isZero();

        ExecResult signResult = softHsmContainer.execInContainer(
                "pkcs11-tool",
                "--module", SoftHsmContainerConfig.LIB_SOFTHSM2_SO,
                "--login", "--pin", pin,
                "--token-label", token,
                "--label", label,
                "--sign",
                "--mechanism", "ECDSA",
                "--input-file", "/tmp/payload.bin",
                "--output-file", "/tmp/signature.bin"
        );

        log.info("Sign stdout: {}", signResult.getStdout().trim());
        if (!signResult.getStderr().isBlank()) {
            log.warn("Sign stderr:\n{}", signResult.getStderr());
        }

        assertThat(signResult.getExitCode())
                .as("pkcs11-tool --sign should exit 0")
                .isZero();

        ExecResult sigSize = softHsmContainer.execInContainer(
                "sh", "-c", "wc -c < /tmp/signature.bin"
        );
        int bytes = Integer.parseInt(sigSize.getStdout().trim());
        log.info("Signature size: {} bytes", bytes);

        assertThat(bytes)
                .as("Signature should be non-empty")
                .isGreaterThan(0);
    }
}

