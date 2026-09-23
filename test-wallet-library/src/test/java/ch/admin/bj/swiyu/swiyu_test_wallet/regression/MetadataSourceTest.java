package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MetadataSourceTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void classpathMetadata_whenValidJson_thenResolvesMountableFile() {
        final MetadataSource source = MetadataSource.resolve("classpath:metadata-source/valid.json");

        assertThat(source.location()).isEqualTo("classpath:metadata-source/valid.json");
        assertThat(source.mountableFile()).isNotNull();
    }

    @Test
    void fileMetadata_whenValidJson_thenResolvesMountableFile() throws IOException {
        final Path metadata = temporaryDirectory.resolve("metadata.json");
        Files.writeString(metadata, "{\"credential_configurations_supported\": {}}");

        final MetadataSource source = MetadataSource.resolve(metadata.toUri().toString());

        assertThat(source.location()).isEqualTo(metadata.toUri().toString());
        assertThat(source.mountableFile()).isNotNull();
    }

    @Test
    void metadata_whenMalformedJson_thenRejectsSource() throws IOException {
        final Path metadata = temporaryDirectory.resolve("invalid.json");
        Files.writeString(metadata, "{not-json}");

        assertThatThrownBy(() -> MetadataSource.resolve(metadata.toUri().toString()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("valid JSON");
    }

    @Test
    void metadata_whenFileDoesNotExist_thenRejectsSource() {
        final Path metadata = temporaryDirectory.resolve("missing.json");

        assertThatThrownBy(() -> MetadataSource.resolve(metadata.toUri().toString()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does not exist or is not readable");
    }

    @Test
    void metadata_whenClasspathResourceDoesNotExist_thenRejectsSource() {
        assertThatThrownBy(() -> MetadataSource.resolve("classpath:missing.json"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does not exist");
    }

    @Test
    void metadata_whenLocationSchemeIsUnsupported_thenRejectsSource() {
        assertThatThrownBy(() -> MetadataSource.resolve("https://example.com/metadata.json"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expected classpath: or file:");
    }
}
