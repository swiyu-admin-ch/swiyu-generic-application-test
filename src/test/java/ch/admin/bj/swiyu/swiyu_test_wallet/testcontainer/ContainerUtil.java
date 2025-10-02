package ch.admin.bj.swiyu.swiyu_test_wallet.testcontainer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ContainerUtil {

    public static Path getResourcePath(String subPath) {
        var path = Paths.get("src/test/resources/").resolve(subPath);

        if (Files.notExists(path)) {
            throw new RuntimeException("file %s does not exists".formatted(path.toAbsolutePath()));
        }

        return path;
    }
}
