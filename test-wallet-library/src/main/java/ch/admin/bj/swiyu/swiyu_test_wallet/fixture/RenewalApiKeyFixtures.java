package ch.admin.bj.swiyu.swiyu_test_wallet.fixture;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class RenewalApiKeyFixtures {
    public static final String RENEWAL_HEADER = "X-Business-Renewal-Key";
    public static final String RENEWAL_VALUE = "application-tests-renewal-key";
    public static final String WEBHOOK_HEADER = "X-Business-Webhook-Key";
    public static final String WEBHOOK_VALUE = "application-tests-webhook-key";
}
