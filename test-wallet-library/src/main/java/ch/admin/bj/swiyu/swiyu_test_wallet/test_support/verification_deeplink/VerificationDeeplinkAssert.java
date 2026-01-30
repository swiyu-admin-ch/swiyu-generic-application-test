package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_deeplink;

import org.assertj.core.api.Assertions;

public final class VerificationDeeplinkAssert {

    private final String deeplink;
    private final String clientId;
    private final String requestUri;

    private VerificationDeeplinkAssert(final String deeplink) {
        this.deeplink = deeplink;
        this.clientId =
                VerificationDeeplinkParser.extractClientId(deeplink);
        this.requestUri =
                VerificationDeeplinkParser.extractRequestUri(deeplink);
    }

    public static VerificationDeeplinkAssert assertThat(
            final String deeplink
    ) {
        return new VerificationDeeplinkAssert(deeplink);
    }

    public VerificationDeeplinkAssert isWellFormed() {
        Assertions.assertThat(clientId)
                .as("verification deeplink client_id")
                .isNotBlank();

        Assertions.assertThat(requestUri)
                .as("verification deeplink request_uri")
                .isNotBlank();

        return this;
    }

    public VerificationDeeplinkAssert hasClientId(
            final String expectedClientId
    ) {
        Assertions.assertThat(clientId)
                .as("verification deeplink client_id")
                .isEqualTo(expectedClientId);

        return this;
    }

    public VerificationDeeplinkAssert hasRequestUri(
            final String expectedRequestUri
    ) {
        Assertions.assertThat(requestUri)
                .as("verification deeplink request_uri")
                .isEqualTo(expectedRequestUri);

        return this;
    }

    public VerificationDeeplinkAssert hasRequestUriStartingWith(
            final String expectedBaseUri
    ) {
        Assertions.assertThat(requestUri)
                .as("verification deeplink request_uri")
                .startsWith(expectedBaseUri);

        return this;
    }
}
