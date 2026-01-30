package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.issuance_deeplink;

import lombok.Value;

import java.net.URI;
import java.util.Map;

@Value
public class IssuanceDeeplink {

    URI uri;
    Map<String, String> params;

    public String credentialOfferRaw() {
        return params.get(IssuanceDeeplinkConstants.CREDENTIAL_OFFER);
    }
}
