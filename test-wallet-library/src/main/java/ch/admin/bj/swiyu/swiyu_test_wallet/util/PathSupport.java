package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import lombok.experimental.UtilityClass;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

@UtilityClass
public class PathSupport {

    public static URI toUri(String url) {
        try {
            return new URI(url);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    public static Map<String, String> splitQuery(URI uri) {
        Map<String, String> queryPairs = new HashMap<>();
        if (uri.getQuery() == null && uri.getQuery().isEmpty()) {
            return queryPairs;
        }

        var queryParts = uri.getQuery().split("&");
        for (String queryPart : queryParts) {
            var keyValue = queryPart.split("=", 2);
            String key = keyValue[0];
            String value = keyValue.length > 1 ? keyValue[1] : "";
            queryPairs.put(key, value);
        }
        return queryPairs;
    }
}
