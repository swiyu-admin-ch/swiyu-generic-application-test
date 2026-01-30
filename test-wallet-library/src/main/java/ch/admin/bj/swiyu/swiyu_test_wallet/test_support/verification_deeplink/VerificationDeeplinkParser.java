package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_deeplink;

import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.deeplink.DeeplinkParser;
import lombok.experimental.UtilityClass;

import java.net.URI;
import java.util.Map;

@UtilityClass
public class VerificationDeeplinkParser {

    public static Map<String, String> parse(final String deeplink) {
        final URI uri = URI.create(deeplink);

        if (!"swiyu-verify".equals(uri.getScheme())) {
            throw new IllegalArgumentException(
                    "Expected swiyu-verify:// deeplink"
            );
        }

        return DeeplinkParser.parse(uri);
    }

    public static String extractClientId(final String deeplink) {
        return parse(deeplink)
                .get(VerificationDeeplinkConstants.CLIENT_ID);
    }

    public static String extractRequestUri(final String deeplink) {
        return parse(deeplink)
                .get(VerificationDeeplinkConstants.REQUEST_URI);
    }
}
