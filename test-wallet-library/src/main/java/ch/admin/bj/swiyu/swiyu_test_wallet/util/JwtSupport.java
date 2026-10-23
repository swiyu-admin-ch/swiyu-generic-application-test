package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import com.nimbusds.jwt.SignedJWT;
import lombok.experimental.UtilityClass;
import tools.jackson.databind.JsonNode;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.JsonConverter.toJsonNode;

@UtilityClass
public class JwtSupport {

    private static final int COMPACT_JWT_PART_COUNT = 3;

    public static String header(String jwt) {
        return parts(jwt)[0];
    }

    public static String payload(String jwt) {
        return parts(jwt)[1];
    }

    public static String decodePayload(String jwt) {
        return new String(Base64.getUrlDecoder().decode(payload(jwt)), StandardCharsets.UTF_8);
    }

    public static JsonNode decodePayloadToJsonNode(String jwt) {
        return toJsonNode(decodePayload(jwt));
    }

    public static String[] parts(String jwt) {
        String[] split = jwt.split("\\.");
        if (split.length != COMPACT_JWT_PART_COUNT) {
            throw new IllegalArgumentException("Invalid JWT format");
        }
        return split;
    }

    public static String signature(String jwt) {
        return parts(jwt)[2];
    }


    public static boolean isCompactJwt(String jwt) {
        return jwt != null && jwt.chars().filter(ch -> ch == '.').count() == 2;
    }

    public static SignedJWT parse(String jwt) {
        try {
            return SignedJWT.parse(jwt);
        } catch (ParseException e) {
            throw new IllegalStateException("Failed to parse JWT", e);
        }
    }
}
