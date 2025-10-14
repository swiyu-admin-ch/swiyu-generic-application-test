package ch.admin.bj.swiyu.swiyu_test_wallet.registry;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import io.ipfs.multibase.Base58;
import lombok.experimental.UtilityClass;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;

import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil.generateSignature;
import static ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil.getVerificationKeyMultibase;

/**
 * Copied from didtoolbox-java <a href="https://github.com/swiyu-admin-ch/didtoolbox-java">...</a>
 * Should be replaced with didtoolbox-java
 */
@UtilityClass
public class JCSHasherUtil {
    public static final String DATA_INTEGRITY_PROOF = "DataIntegrityProof";
    public static final String EDDSA_JCS_2022 = "eddsa-jcs-2022";
    public static final String DID_KEY = "did:key:";
    public static final String PROOF_PURPOSE_AUTHENTICATION = "authentication";
    public static final String PROOF_PURPOSE_ASSERTION_METHOD = "assertionMethod";

    public static String buildSCID(String jsonData) throws IOException {
        return Base58.encode(multihash((new JsonCanonicalizer(jsonData)).getEncodedString()));
    }

    static byte[] multihash(String str) {

        MessageDigest hasher = null;
        try {
            hasher = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
        hasher.update(str.getBytes(StandardCharsets.UTF_8));
        byte[] digest = hasher.digest();

        // multihash is an implementation of the multihash specification (https://www.w3.org/TR/controller-document/#multihash).
        // Its output is a hash of the input using the associated <hash algorithm>, prefixed with a hash algorithm identifier and the hash size.
        // Multihash Identifier	Multihash Header	Description
        // sha2-256	            0x12	            SHA-2 with 256 bits (32 bytes) of output, as defined by [RFC6234].
        ByteBuffer buff = ByteBuffer.allocate(2 + digest.length);
        buff.put((byte) 0x12);          // hash algorithm (sha2-256) identifier
        buff.put((byte) digest.length); // hash size (in bytes)
        buff.put(digest);

        return buff.array();
    }

    private static String hashAsHex(String json) throws IOException {

        MessageDigest hasher = null;
        try {
            hasher = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
        hasher.update(((new JsonCanonicalizer(json)).getEncodedString()).getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hasher.digest());
    }

    static String hashJsonObjectAsHex(JsonObject json) throws IOException {
        return hashAsHex(json.toString());
    }

    static String hashJsonArrayAsHex(JsonArray json) throws IOException {
        return hashAsHex(json.toString());
    }

    public static JsonObject buildDataIntegrityProof(JsonObject unsecuredDocument,
                                                     boolean useContext,
                                                     String challenge,
                                                     String proofPurpose,
                                                     ZonedDateTime dateTime,
                                                     KeyPair keyPair)
            throws IOException {

        JsonObject proof = new JsonObject();

        // If unsecuredDocument.@context is present, set proof.@context to unsecuredDocument.@context.
        var ctx = unsecuredDocument.get("@context");
        if (ctx != null && useContext) {
            proof.add("@context", ctx);
        }

        proof.addProperty("type", DATA_INTEGRITY_PROOF);
        // According to https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022
        proof.addProperty("cryptosuite", EDDSA_JCS_2022);
        proof.addProperty("created", DateTimeFormatter.ISO_INSTANT.format(dateTime.truncatedTo(ChronoUnit.SECONDS)));
        proof.addProperty("verificationMethod", DID_KEY + getVerificationKeyMultibase(keyPair.getPublic().getEncoded()) + '#' + getVerificationKeyMultibase(keyPair.getPublic().getEncoded()));
        proof.addProperty("proofPurpose", proofPurpose);
        if (challenge != null) {
            proof.addProperty("challenge", challenge);
        }

        String docHashHex = hashJsonObjectAsHex(unsecuredDocument);
        String proofHashHex = hashJsonObjectAsHex(proof);

        var signature = generateSignature(keyPair, HexFormat.of().parseHex(proofHashHex + docHashHex));
        proof.addProperty("proofValue", 'z' + Base58.encode(signature));

        return proof;
    }
}
