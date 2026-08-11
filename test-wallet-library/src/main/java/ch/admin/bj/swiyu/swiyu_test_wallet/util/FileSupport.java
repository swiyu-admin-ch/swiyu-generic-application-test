package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;

public class FileSupport {

    public static void deleteDirectory(final Path path) throws IOException {
        if (!Files.exists(path)) return;

        final List<Path> pathsToDelete;
        try (var paths = Files.walk(path)) {
            pathsToDelete = paths.sorted(Comparator.reverseOrder()).toList();
        }

        for (Path entry : pathsToDelete) {
            Files.delete(entry);
        }
    }

}
