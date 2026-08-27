package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import org.testcontainers.utility.MountableFile;

import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * A validated JSON metadata source that can be mounted into a regression component container.
 *
 * <p>Resolution is eager: the source must exist, be readable and contain valid JSON before any regression container is
 * started. Supported locations are {@code classpath:...} and {@code file:...}.
 */
public final class MetadataSource {

    private static final String CLASSPATH_PREFIX = "classpath:";
    private static final String FILE_PREFIX = "file:";

    private final String configuredLocation;
    private final MountableFile containerMount;

    private MetadataSource(final String location, final MountableFile mountableFile) {
        this.configuredLocation = location;
        this.containerMount = mountableFile;
    }

    /**
     * Resolves and validates a configured metadata location.
     *
     * @param location a {@code classpath:} resource or {@code file:} URI
     * @return the original location and its Testcontainers mount representation
     * @throws IllegalArgumentException if the scheme is unsupported or the source is missing, unreadable or invalid JSON
     */
    public static MetadataSource resolve(final String location) {
        if (location == null || location.isBlank()) {
            throw new IllegalArgumentException("Metadata location must not be blank");
        }

        if (location.startsWith(CLASSPATH_PREFIX)) {
            return resolveClasspath(location);
        }
        if (location.startsWith(FILE_PREFIX)) {
            return resolveFile(location);
        }

        throw new IllegalArgumentException(
                "Unsupported metadata location '%s'; expected classpath: or file:".formatted(location)
        );
    }

    /**
     * Returns the original configured location used in diagnostics and reports.
     *
     * @return configured {@code classpath:} or {@code file:} location
     */
    public String location() {
        return configuredLocation;
    }

    /**
     * Returns the already validated source in the form expected by Testcontainers.
     *
     * @return mountable metadata source
     */
    public MountableFile mountableFile() {
        return containerMount;
    }

    private static MetadataSource resolveClasspath(final String location) {
        final String resourcePath = classpathResourcePath(location);
        MetadataJsonValidator.validateClasspath(resourcePath, location);
        return new MetadataSource(location, MountableFile.forClasspathResource(resourcePath));
    }

    private static String classpathResourcePath(final String location) {
        final String resourcePath = removeLeadingSlash(location.substring(CLASSPATH_PREFIX.length()));
        if (resourcePath.isBlank()) {
            throw new IllegalArgumentException("Classpath metadata resource must not be blank");
        }
        return resourcePath;
    }

    private static MetadataSource resolveFile(final String location) {
        final Path path = filePath(location).toAbsolutePath().normalize();
        MetadataJsonValidator.validateFile(path, location);
        return new MetadataSource(location, MountableFile.forHostPath(path));
    }

    private static Path filePath(final String location) {
        final String pathValue = location.substring(FILE_PREFIX.length());
        if (pathValue.isBlank()) {
            throw new IllegalArgumentException("Metadata file path must not be blank");
        }

        try {
            final URI uri = URI.create(location);
            if (!uri.isOpaque()) {
                return Paths.get(uri);
            }
            return Paths.get(pathValue);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException(
                    "Invalid metadata file location '%s'".formatted(location),
                    exception
            );
        }
    }

    private static String removeLeadingSlash(final String value) {
        return value.startsWith("/") ? value.substring(1) : value;
    }
}
