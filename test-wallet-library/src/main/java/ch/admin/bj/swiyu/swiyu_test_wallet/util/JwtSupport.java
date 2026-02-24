package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import lombok.experimental.UtilityClass;

import java.text.ParseException;
import java.util.Base64;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.JsonConverter.toJsonNode;

@UtilityClass
public class JwtSupport {

    public static String header(String jwt) {
        return parts(jwt)[0];
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
        String[] split = jwt.split("\\.");
        if (split.length != 3) {
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
