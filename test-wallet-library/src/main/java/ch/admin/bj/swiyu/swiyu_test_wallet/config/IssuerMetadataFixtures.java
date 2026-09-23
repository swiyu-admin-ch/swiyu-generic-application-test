package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import lombok.experimental.UtilityClass;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

@UtilityClass
public class IssuerMetadataFixtures {

    private static final String STANDARD_METADATA = "issuer/metadata.json";
    private static final String BOUND_CREDENTIAL_CONFIGURATION = "bound_example_sd_jwt";
    private static final String ED25519 = "Ed25519";

    /**
     * Builds isolated issuer metadata that advertises Ed25519 for OID4VCI Proof JWTs.
     *
     * <p>The standard metadata remains unchanged so older issuer images can still start for unrelated tests.</p>
     */
    public static MountableFile cryptoAgilityMetadata() {
        try (InputStream metadata = IssuerMetadataFixtures.class
                .getClassLoader()
                .getResourceAsStream(STANDARD_METADATA)) {
            if (metadata == null) {
                throw new IllegalStateException("Missing issuer metadata fixture: " + STANDARD_METADATA);
            }

            final JsonObject root = JsonParser.parseReader(
                    new InputStreamReader(metadata, StandardCharsets.UTF_8)
            ).getAsJsonObject();
            final JsonArray supportedAlgorithms = root
                    .getAsJsonObject("credential_configurations_supported")
                    .getAsJsonObject(BOUND_CREDENTIAL_CONFIGURATION)
                    .getAsJsonObject("proof_types_supported")
                    .getAsJsonObject("jwt")
                    .getAsJsonArray("proof_signing_alg_values_supported");

            boolean ed25519Advertised = false;
            for (JsonElement algorithm : supportedAlgorithms) {
                if (ED25519.equals(algorithm.getAsString())) {
                    ed25519Advertised = true;
                    break;
                }
            }
            if (!ed25519Advertised) {
                supportedAlgorithms.add(ED25519);
            }

            final Path generatedMetadata = Files.createTempFile("issuer-crypto-agility-metadata-", ".json");
            Files.writeString(generatedMetadata, root.toString(), StandardCharsets.UTF_8);
            generatedMetadata.toFile().deleteOnExit();
            return MountableFile.forHostPath(generatedMetadata, 0444);
        } catch (IOException exception) {
            throw new IllegalStateException("Failed to build crypto-agility issuer metadata", exception);
        }
    }
}
