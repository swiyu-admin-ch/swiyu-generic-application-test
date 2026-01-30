package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.deeplink;

import lombok.experimental.UtilityClass;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

@UtilityClass
public class DeeplinkParser {

    public static Map<String, String> parse(final URI uri) {
        if (uri.getQuery() == null) {
            return Map.of();
        }

        return Arrays.stream(uri.getQuery().split("&"))
                .map(p -> p.split("=", 2))
                .collect(Collectors.toMap(
                        p -> URLDecoder.decode(p[0], StandardCharsets.UTF_8),
                        p -> p.length > 1
                                ? URLDecoder.decode(p[1], StandardCharsets.UTF_8)
                                : ""
                ));
    }
}
