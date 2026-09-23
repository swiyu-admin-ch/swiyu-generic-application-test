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
        return createDidLog(authenticationKey, assertionMethodKeys, identifierRegistryUrl, false);
    }

    public static String createDidLog(JWK authenticationKey, JWK assertionMethodKeys, URI identifierRegistryUrl,
                                      boolean useAbsolutePublicKeyJwkKid) {

        var keyPair = KeyUtil.getEd25519VerificationMethodKeyPair();

        ZonedDateTime zdt = ZonedDateTime.now();

        JsonObject didDoc = createDidDoc(
                identifierRegistryUrl,
                List.of(authenticationKey),
                List.of(assertionMethodKeys),
                useAbsolutePublicKeyJwkKid);


        var didLogEntryWithoutProofAndSignature = new JsonObject();
        didLogEntryWithoutProofAndSignature.addProperty("versionId", SCID_PLACEHOLDER);
        didLogEntryWithoutProofAndSignature.addProperty(
                "versionTime",
                DateTimeFormatter.ISO_INSTANT.format(zdt.truncatedTo(ChronoUnit.SECONDS))
        );
        didLogEntryWithoutProofAndSignature.add("parameters", createDidParams(keyPair));
        didLogEntryWithoutProofAndSignature.add("state", didDoc);

        String scid = null;
        try {
            scid = JCSHasherUtil.buildSCID(didLogEntryWithoutProofAndSignature.toString());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        String didLogEntryWithoutProofAndSignatureWithSCID = didLogEntryWithoutProofAndSignature.toString().replace(SCID_PLACEHOLDER, scid);
        JsonObject didLogEntryWithSCIDWithoutProofAndSignature = JsonParser
                .parseString(didLogEntryWithoutProofAndSignatureWithSCID)
                .getAsJsonObject();

        String entryHash = null;
        try {
            entryHash = JCSHasherUtil.buildSCID(didLogEntryWithSCIDWithoutProofAndSignature.toString());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        JsonObject didLogEntryWithProof = new JsonObject();
        var versionId = "1-" + entryHash;
        didLogEntryWithProof.addProperty("versionId", versionId);
        didLogEntryWithProof.add("versionTime", didLogEntryWithSCIDWithoutProofAndSignature.get("versionTime"));
        didLogEntryWithProof.add("parameters", didLogEntryWithSCIDWithoutProofAndSignature.get("parameters"));
        didLogEntryWithProof.add("state", didLogEntryWithSCIDWithoutProofAndSignature.get("state"));

        JsonArray proofs = new JsonArray();
        try {
            proofs.add(JCSHasherUtil.buildDataIntegrityProof(
                    didLogEntryWithProof,
                    false,
                    null,
                    JCSHasherUtil.PROOF_PURPOSE_ASSERTION_METHOD,
                    zdt,
                    keyPair
            ));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        didLogEntryWithProof.add("proof", proofs);

        return didLogEntryWithProof.toString();
    }

    private JsonObject createDidDoc(URI identifierRegistryUrl,
                                    List<JWK> authenticationKeys,
                                    List<JWK> assertionMethodKeys,
                                    boolean useAbsolutePublicKeyJwkKid) {

        if (isNull(authenticationKeys) || isNull(assertionMethodKeys)) {
            throw new IllegalArgumentException("At least one authentication key and one assertion method key must be provided");
        }

        var didWebvh = getDidWebvh(identifierRegistryUrl);

        var context = new JsonArray();
        context.add("https://www.w3.org/ns/did/v1");
        context.add("https://w3id.org/security/jwk/v1");

        var didDoc = new JsonObject();
        didDoc.add("@context", context);
        didDoc.addProperty("id", didWebvh);

        JsonArray verificationMethod = new JsonArray();

        if (!authenticationKeys.isEmpty()) {

            JsonArray authentication = new JsonArray();
            for (var i = 0; i < authenticationKeys.size(); i++) {
                var keyType = "auth-key-%02d".formatted(i + 1);
                authentication.add(didWebvh + "#" + keyType);
                verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(
                        didWebvh,
                        keyType,
                        authenticationKeys.get(i),
                        useAbsolutePublicKeyJwkKid));
            }

            didDoc.add("authentication", authentication);

        }

        if (!assertionMethodKeys.isEmpty()) {

            JsonArray assertionMethod = new JsonArray();
            for (var i = 0; i < assertionMethodKeys.size(); i++) {
                var keyType = "assert-key-%02d".formatted(i + 1);
                assertionMethod.add(didWebvh + "#" + keyType);
                verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(
                        didWebvh,
                        keyType,
                        assertionMethodKeys.get(i),
                        useAbsolutePublicKeyJwkKid));
            }
            didDoc.add("assertionMethod", assertionMethod);
        }

        didDoc.add("verificationMethod", verificationMethod);

        return didDoc;
    }

    private static String getDidWebvh(URI identifierRegistryUrl) {
        var didWebvh = "%s:{SCID}:%s".formatted("did:webvh", identifierRegistryUrl.getHost());
        int port = identifierRegistryUrl.getPort();
        if (port != -1) {
            didWebvh = "%s%%3A%d".formatted(didWebvh, port);
        }
        String path = identifierRegistryUrl.getPath();
        if (!path.isEmpty()) {
            didWebvh = "%s%s".formatted(didWebvh,
                    path.replace("/did.jsonl", "")
                            .replace("/", ":"));
        }
        return didWebvh;
    }

    private JsonObject buildVerificationMethodWithPublicKeyJwk(String didWebvh, String keyType, JWK privateJwk,
                                                               boolean useAbsolutePublicKeyJwkKid) {

        final String verificationMethodId = didWebvh + "#" + keyType;
        String publicKeyJwk = privateJwk.toPublicJWK().toJSONString();
        JsonObject publicKeyJwkObject = JsonParser.parseString(publicKeyJwk).getAsJsonObject();
        publicKeyJwkObject.addProperty("kid", useAbsolutePublicKeyJwkKid ? verificationMethodId : keyType);

        JsonObject verificationMethodObj = new JsonObject();
        verificationMethodObj.addProperty("id", verificationMethodId);
        verificationMethodObj.addProperty("type", "JsonWebKey2020");
        verificationMethodObj.addProperty("controller", didWebvh);
        verificationMethodObj.add("publicKeyJwk", publicKeyJwkObject);

        return verificationMethodObj;
    }

    private JsonObject createDidParams(KeyPair keyPair) {

        JsonObject didMethodParameters = new JsonObject();
        didMethodParameters.addProperty("method", "did:webvh:1.0");
        didMethodParameters.addProperty("scid", SCID_PLACEHOLDER);

        var updateKeysJsonArray = new JsonArray();
        updateKeysJsonArray.add(getVerificationKeyMultibase(keyPair.getPublic().getEncoded()));

        didMethodParameters.add("updateKeys", updateKeysJsonArray);
        didMethodParameters.addProperty("portable", false);

        return didMethodParameters;
    }

    public static String getDidFromDidLog(String didLog) {
        return JsonParser.parseString(didLog)
                .getAsJsonObject()
                .getAsJsonObject("state")
                .get("id")
                .getAsString();
    }
}
