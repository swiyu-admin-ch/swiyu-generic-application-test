package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_response;

import com.google.gson.JsonObject;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class CredentialResponse {

    private final int status;
    private final JsonObject body;
    private final String rawBody;
}
