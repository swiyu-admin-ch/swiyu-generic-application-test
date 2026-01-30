package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt;

import lombok.experimental.UtilityClass;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

@UtilityClass
public class SdJwtParser {

    public static String header(final String sdJwt) {
        return decodeBase64Url(sdJwt.split("\\.")[0]);
    }

    public static String payload(final String sdJwt) {
        return decodeBase64Url(sdJwt.split("\\.")[1]);
    }

    public static List<String> disclosures(final String sdJwt) {
        return Arrays.stream(sdJwt.split("~"))
                .skip(1)
                .filter(p -> !p.contains("."))
                .map(SdJwtParser::decodeBase64Url)
                .toList();
    }

    public static Optional<String> keyBindingJwt(final String sdJwt) {
        return Arrays.stream(sdJwt.split("~"))
                .filter(p -> p.contains("."))
                .findFirst();
    }

    private static String decodeBase64Url(final String value) {
        return new String(
                Base64.getUrlDecoder().decode(value),
                StandardCharsets.UTF_8
        );
    }
}
