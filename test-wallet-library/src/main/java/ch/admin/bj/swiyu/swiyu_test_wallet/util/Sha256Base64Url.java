package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import lombok.experimental.UtilityClass;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * {@code base64url(SHA-256(US-ASCII(text)))}, the one hash the wallet needs three times:
 * <ul>
 *     <li>the DPoP {@code ath} claim (RFC 9449 §4.2),</li>
 *     <li>the Key Binding JWT {@code sd_hash} claim (RFC 9901 §4.3.1),</li>
 *     <li>the digest of a Disclosure (RFC 9901 §4.2.3).</li>
 * </ul>
 *
 * <p>Written from the specifications on purpose, not taken from {@code swiyu-generic-java-lib}: the Credential Issuer and the
 * Verifier validate with that library, so computing the expected value with the same code would hide a library defect.
 */
@UtilityClass
public class Sha256Base64Url {

    public static String ofUsAscii(final String text) {
        try {
            final byte[] hash = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
