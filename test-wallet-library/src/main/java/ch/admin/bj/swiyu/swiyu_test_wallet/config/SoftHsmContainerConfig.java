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

    public static final String LIB_SOFTHSM2_SO = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so";
}