package ch.admin.bj.swiyu.swiyu_test_wallet.mock;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * What the Status Registry checks on a Status List Token uploaded to its v2 update endpoint, on top of the checks of v1
 * (operation {@code updateStatusListEntry} of {@code SWIYU_Core_Business_status.yaml}): the Swiss profile conformity of the
 * token.
 *
 * <ul>
 *   <li>the JWT header {@code typ} is {@code statuslist+jwt};</li>
 *   <li>the JWT header {@code profile_version} is {@code swiss-profile-vc:1.0.0};</li>
 *   <li>the {@code exp} claim is set;</li>
 *   <li>the decompressed {@code lst} does not exceed 200 KB;</li>
 *   <li>{@code bits} is 1, 2, 4 or 8 (Token Status List draft 20 §4.2). The v2 rule that the decompressed bit count is
 *   byte-aligned and aligned with {@code bits} holds for every decompressed byte array under that rule, so it needs no
 *   check of its own.</li>
 * </ul>
 *
 * <p>Unknown: whether the registry counts 200 KB as 200,000 or as 204,800 bytes. The mock accepts the larger value, so it
 * never rejects what the registry would accept.
 *
 * <p>The signature is not checked: v2 does not state that it is.
 */
final class SwissStatusListConformity {

    static final String TYPE = "statuslist+jwt";
    static final String PROFILE_VERSION = "swiss-profile-vc:1.0.0";
    static final String PROFILE_VERSION_PARAM = "profile_version";
    static final int MAX_DECOMPRESSED_BYTES = 200 * 1024;

    private static final List<Integer> VALID_BITS = List.of(1, 2, 4, 8);

    private SwissStatusListConformity() {
    }

    /** The reasons the Status List Token is not conformant; empty when it is. */
    static List<String> violations(final String compactJwt) {
        final SignedJWT jwt;
        final JWTClaimsSet claims;
        try {
            jwt = SignedJWT.parse(compactJwt);
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException | NullPointerException e) {
            return List.of("the body is not a signed JWT in compact serialization");
        }

        final List<String> violations = new ArrayList<>();
        final JWSHeader header = jwt.getHeader();
        if (header.getType() == null || !TYPE.equals(header.getType().getType())) {
            violations.add("JWT header 'typ' must be '" + TYPE + "'");
        }
        if (!PROFILE_VERSION.equals(header.getCustomParam(PROFILE_VERSION_PARAM))) {
            violations.add("JWT header '" + PROFILE_VERSION_PARAM + "' must be '" + PROFILE_VERSION + "'");
        }
        if (claims.getExpirationTime() == null) {
            violations.add("claim 'exp' must be set");
        }
        violations.addAll(statusListViolations(claims.getClaim("status_list")));
        return violations;
    }

    private static List<String> statusListViolations(final Object statusListClaim) {
        if (!(statusListClaim instanceof Map<?, ?> statusList)
                || !(statusList.get("lst") instanceof String lst)
                || !(statusList.get("bits") instanceof Number bits)) {
            return List.of("claim 'status_list' must contain the integer 'bits' and the string 'lst'");
        }

        final List<String> violations = new ArrayList<>();
        if (!VALID_BITS.contains(bits.intValue()) || bits.doubleValue() != bits.intValue()) {
            violations.add("'bits' must be 1, 2, 4 or 8");
        }
        decompressedViolation(lst).ifPresent(violations::add);
        return violations;
    }

    /** {@code lst} is base64url without padding of a ZLIB stream (Token Status List draft 20 §4.1). */
    private static Optional<String> decompressedViolation(final String lst) {
        final byte[] compressed;
        try {
            compressed = Base64.getUrlDecoder().decode(lst);
        } catch (IllegalArgumentException e) {
            return Optional.of("'lst' is not base64url");
        }

        final Inflater inflater = new Inflater();
        inflater.setInput(compressed);
        final byte[] buffer = new byte[8192];
        long total = 0;
        try {
            while (!inflater.finished()) {
                final int read = inflater.inflate(buffer);
                if (read == 0 && (inflater.needsInput() || inflater.needsDictionary())) {
                    return Optional.of("'lst' is not a complete ZLIB stream");
                }
                total += read;
                if (total > MAX_DECOMPRESSED_BYTES) {
                    return Optional.of("decompressed 'lst' exceeds 200 KB");
                }
            }
        } catch (DataFormatException e) {
            return Optional.of("'lst' is not a ZLIB stream");
        } finally {
            inflater.end();
        }
        return Optional.empty();
    }
}
