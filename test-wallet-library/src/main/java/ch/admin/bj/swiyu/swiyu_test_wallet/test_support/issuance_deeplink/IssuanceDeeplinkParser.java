package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.issuance_deeplink;

import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.deeplink.DeeplinkParser;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.TestSupportException;
import lombok.experimental.UtilityClass;

import java.net.URI;
import java.util.Map;

@UtilityClass
public class IssuanceDeeplinkParser {

    public static Map<String, String> parse(final String deeplink) {
        final URI uri = URI.create(deeplink);

        if (!IssuanceDeeplinkConstants.PROTOCOL.equals(uri.getScheme())) {
            throw new TestSupportException("Expected swiyu:// issuance deeplink");
        }

        return DeeplinkParser.parse(uri);
    }

    public static String extractCredentialOfferJson(
            final String deeplink
    ) {
        return parse(deeplink)
                .get(IssuanceDeeplinkConstants.CREDENTIAL_OFFER);
    }
}
