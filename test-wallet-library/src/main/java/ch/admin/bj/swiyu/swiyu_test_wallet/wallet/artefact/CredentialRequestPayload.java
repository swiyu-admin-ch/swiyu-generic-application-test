package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import lombok.experimental.UtilityClass;

/** Deliberate deviations of the OID4VCI Credential Request plaintext, before transport encryption. */
@UtilityClass
public class CredentialRequestPayload {

    /** Omits only {@code proofs}, violating OID4VCI §8.2 when the requested configuration requires holder binding. */
    public static String withoutHolderBindingProofs(final String validRequest) {
        final JsonObject request = JsonParser.parseString(validRequest).getAsJsonObject();
        if (request.remove("proofs") == null) {
            throw new IllegalArgumentException("The original Credential Request must contain proofs");
        }
        return request.toString();
    }
}
