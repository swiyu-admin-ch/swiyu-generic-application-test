package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/** Validates metadata content independently from its Testcontainers mount representation. */
final class MetadataJsonValidator {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private MetadataJsonValidator() {
    }

    static void validateClasspath(final String resourcePath, final String location) {
        try (InputStream metadata = MetadataJsonValidator.class.getResourceAsStream("/" + resourcePath)) {
            if (metadata == null) {
                throw new IllegalArgumentException(
                        "Metadata classpath resource '%s' does not exist".formatted(resourcePath)
                );
            }
            validateJson(metadata, location);
        } catch (JacksonException exception) {
            throw invalidJson(location, exception);
        } catch (IOException exception) {
            throw unreadable(location, exception);
        }
    }

    static void validateFile(final Path path, final String location) {
        if (!Files.isRegularFile(path) || !Files.isReadable(path)) {
            throw new IllegalArgumentException(
                    "Metadata file '%s' does not exist or is not readable".formatted(path)
            );
        }

        try (InputStream metadata = Files.newInputStream(path)) {
            validateJson(metadata, location);
        } catch (JacksonException exception) {
            throw invalidJson(location, exception);
        } catch (IOException exception) {
            throw unreadable(location, exception);
        }
    }

    private static void validateJson(final InputStream metadata, final String location) throws IOException {
        if (OBJECT_MAPPER.readTree(metadata) == null) {
            throw new IllegalArgumentException("Metadata source '%s' is empty".formatted(location));
        }
    }

    private static IllegalArgumentException unreadable(final String location, final IOException exception) {
        return new IllegalArgumentException(
                "Metadata source '%s' is not readable".formatted(location),
                exception
        );
    }

    private static IllegalArgumentException invalidJson(final String location, final JacksonException exception) {
        return new IllegalArgumentException(
                "Metadata source '%s' is not valid JSON".formatted(location),
                exception
        );
    }
}
