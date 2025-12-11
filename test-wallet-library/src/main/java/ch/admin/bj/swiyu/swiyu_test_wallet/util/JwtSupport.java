package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.experimental.UtilityClass;

import java.util.Base64;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.JsonConverter.toJsonNode;

@UtilityClass
public class JwtSupport {

    public static String header(String jwt) {
        return parts(jwt)[0];
    }

    public static String decodeHeader(String jwt) {
        return new String(Base64.getUrlDecoder().decode(header(jwt)));
    }

    public static JsonNode decodeHeaderAsJsonNode(String jwt) {
        return toJsonNode(decodeHeader(jwt));
    }

    public static String payload(String jwt) {
        return parts(jwt)[1];
    }

    public static String decodePayload(String jwt) {
        return new String(Base64.getUrlDecoder().decode(payload(jwt)));
    }

    public static JsonNode decodePayloadToJsonNode(String jwt) {
        return toJsonNode(decodePayload(jwt));
    }

    public static String[] parts(String jwt) {
        return jwt.split("\\.");
    }
}
