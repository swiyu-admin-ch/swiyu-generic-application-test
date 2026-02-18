package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import lombok.experimental.UtilityClass;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.TestSupportException;

@UtilityClass
public class ContainerUtil {

    public static Path getResourcePath(String subPath) {
        var path = Paths.get("src/test/resources/").resolve(subPath);

        if (Files.notExists(path)) {
            throw new TestSupportException("file %s does not exists".formatted(path.toAbsolutePath()));
        }

        return path;
    }
}
