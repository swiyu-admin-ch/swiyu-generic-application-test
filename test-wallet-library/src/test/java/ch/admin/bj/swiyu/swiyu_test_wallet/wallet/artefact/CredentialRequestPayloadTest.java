package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CredentialRequestPayloadTest {

    @Test
    void withoutHolderBindingProofs_whenRequestIsValid_thenOnlyProofsAreRemoved() {
        final String validRequest = """
                {
                  "credential_configuration_id": "bound_example_sd_jwt",
                  "proofs": {"jwt": ["first-proof", "second-proof"]},
                  "credential_response_encryption": {"enc": "A256GCM", "jwk": {"kty": "EC", "x": "x", "y": "y"}}
                }
                """;
        final JsonObject original = JsonParser.parseString(validRequest).getAsJsonObject();

        final JsonObject withoutProofs = JsonParser.parseString(
                CredentialRequestPayload.withoutHolderBindingProofs(validRequest)).getAsJsonObject();

        assertThat(withoutProofs.has("proofs"))
                .isFalse();
        withoutProofs.add("proofs", original.get("proofs"));
        assertThat(withoutProofs)
                .isEqualTo(original);
    }

    @Test
    void withoutHolderBindingProofs_whenProofsAreAlreadyMissing_thenRejectsTheAmbiguousDeviation() {
        assertThatThrownBy(() -> CredentialRequestPayload.withoutHolderBindingProofs(
                "{\"credential_configuration_id\":\"bound_example_sd_jwt\"}"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must contain proofs");
    }
}
