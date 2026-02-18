package ch.admin.bj.swiyu.swiyu_test_wallet.registry;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.jwk.JWK;
import lombok.experimental.UtilityClass;

import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil.getVerificationKeyMultibase;
import static java.util.Objects.isNull;

/**
 * Copied from didtoolbox-java <a href="https://github.com/swiyu-admin-ch/didtoolbox-java">...</a>
 * Should be replaced with didtoolbox-java
 */
@UtilityClass
public class DidLogUtil {

    private static final String SCID_PLACEHOLDER = "{SCID}";

    public static String createDidLog(JWK authenticationKey, JWK assertionMethodKeys, URI identifierRegistryUrl) {

        var keyPair = KeyUtil.getEd25519VerificationMethodKeyPair();

        ZonedDateTime zdt = ZonedDateTime.now();

        JsonObject didDoc = createDidDoc(identifierRegistryUrl, List.of(authenticationKey), List.of(assertionMethodKeys));


        var didLogEntryWithoutProofAndSignature = new JsonArray();
        didLogEntryWithoutProofAndSignature.add(SCID_PLACEHOLDER);
        didLogEntryWithoutProofAndSignature.add(DateTimeFormatter.ISO_INSTANT.format(zdt.truncatedTo(ChronoUnit.SECONDS)));

        didLogEntryWithoutProofAndSignature.add(createDidParams(keyPair));

        JsonObject initialDidDoc = new JsonObject();
        initialDidDoc.add("value", didDoc);
        didLogEntryWithoutProofAndSignature.add(initialDidDoc);

        String scid = null;
        try {
            scid = JCSHasherUtil.buildSCID(didLogEntryWithoutProofAndSignature.toString());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        String didDocWithSCID = didDoc.toString().replace(SCID_PLACEHOLDER, scid);
        didDoc = JsonParser.parseString(didDocWithSCID).getAsJsonObject();

        String didLogEntryWithoutProofAndSignatureWithSCID = didLogEntryWithoutProofAndSignature.toString().replace(SCID_PLACEHOLDER, scid);
        JsonArray didLogEntryWithSCIDWithoutProofAndSignature = JsonParser.parseString(didLogEntryWithoutProofAndSignatureWithSCID).getAsJsonArray();

        String entryHash = null;
        try {
            entryHash = JCSHasherUtil.buildSCID(didLogEntryWithSCIDWithoutProofAndSignature.toString());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        JsonArray didLogEntryWithProof = new JsonArray();
        var challenge = "1-" + entryHash; // versionId as the proof challenge
        didLogEntryWithProof.add(challenge);
        didLogEntryWithProof.add(didLogEntryWithSCIDWithoutProofAndSignature.get(1));
        didLogEntryWithProof.add(didLogEntryWithSCIDWithoutProofAndSignature.get(2));
        didLogEntryWithProof.add(didLogEntryWithSCIDWithoutProofAndSignature.get(3));

        JsonArray proofs = new JsonArray();
        try {
            proofs.add(JCSHasherUtil.buildDataIntegrityProof(
                    didDoc, false, challenge, JCSHasherUtil.PROOF_PURPOSE_AUTHENTICATION, zdt, keyPair
            ));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        didLogEntryWithProof.add(proofs);

        return didLogEntryWithProof.toString();
    }

    private JsonObject createDidDoc(URI identifierRegistryUrl,
                                    List<JWK> authenticationKeys,
                                    List<JWK> assertionMethodKeys) {

        if (isNull(authenticationKeys) || isNull(assertionMethodKeys)) {
            throw new IllegalArgumentException("At least one authentication key and one assertion method key must be provided");
        }

        var didTDW = getDidTDW(identifierRegistryUrl);

        var context = new JsonArray();
        context.add("https://www.w3.org/ns/did/v1");
        context.add("https://w3id.org/security/jwk/v1");

        var didDoc = new JsonObject();
        didDoc.add("@context", context);
        didDoc.addProperty("id", didTDW);

        JsonArray verificationMethod = new JsonArray();

        if (!authenticationKeys.isEmpty()) {

            JsonArray authentication = new JsonArray();
            for (var i = 0; i < authenticationKeys.size(); i++) {
                var keyType = "auth-key-%02d".formatted(i + 1);
                authentication.add(didTDW + "#" + keyType);
                verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(didTDW, keyType, authenticationKeys.get(i)));
            }

            didDoc.add("authentication", authentication);

        }

        if (!assertionMethodKeys.isEmpty()) {

            JsonArray assertionMethod = new JsonArray();
            for (var i = 0; i < assertionMethodKeys.size(); i++) {
                var keyType = "assert-key-%02d".formatted(i + 1);
                assertionMethod.add(didTDW + "#" + keyType);
                verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(didTDW, keyType, assertionMethodKeys.get(i)));
            }
            didDoc.add("assertionMethod", assertionMethod);
        }

        didDoc.add("verificationMethod", verificationMethod);

        return didDoc;
    }

    private static String getDidTDW(URI identifierRegistryUrl) {
        var didTDW = "%s:{SCID}:%s".formatted("did:tdw", identifierRegistryUrl.getHost());
        int port = identifierRegistryUrl.getPort();
        if (port != -1) {
            didTDW = "%s%%3A%d".formatted(didTDW, port);
        }
        String path = identifierRegistryUrl.getPath();
        if (!path.isEmpty()) {
            didTDW = "%s%s".formatted(didTDW,
                    path.replace("/did.jsonl", "")
                            .replace("/", ":"));
        }
        return didTDW;
    }

    private JsonObject buildVerificationMethodWithPublicKeyJwk(String didTDW, String keyType, JWK privateJwk) {

        String publicKeyJwk = privateJwk.toPublicJWK().toJSONString();

        JsonObject verificationMethodObj = new JsonObject();
        verificationMethodObj.addProperty("id", didTDW + "#" + keyType);
        verificationMethodObj.addProperty("type", "JsonWebKey2020");
        verificationMethodObj.addProperty("controller", didTDW);
        verificationMethodObj.add("publicKeyJwk", JsonParser.parseString(publicKeyJwk).getAsJsonObject());

        return verificationMethodObj;
    }

    private JsonObject createDidParams(KeyPair keyPair) {

        JsonObject didMethodParameters = new JsonObject();
        didMethodParameters.addProperty("method", "did:tdw:0.3");
        didMethodParameters.addProperty("scid", SCID_PLACEHOLDER);

        var updateKeysJsonArray = new JsonArray();
        updateKeysJsonArray.add(getVerificationKeyMultibase(keyPair.getPublic().getEncoded()));

        didMethodParameters.add("updateKeys", updateKeysJsonArray);
        didMethodParameters.addProperty("portable", false);

        return didMethodParameters;
    }

    public static String getDidFromDidLog(String didLog) {
        JsonArray didLogArray = JsonParser.parseString(didLog).getAsJsonArray();
        JsonObject didParams = didLogArray.get(3).getAsJsonObject();
        JsonObject values = didParams.get("value").getAsJsonObject();
        return values.get("id").getAsString();
    }
}
