package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_response;

import ch.admin.bj.swiyu.swiyu_test_wallet.util.JWESupport;
import com.google.gson.JsonObject;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;

@Slf4j
public final class CredentialResponseAssert {

    private final CredentialResponse response;
    private final JsonObject body;

    private CredentialResponseAssert(final CredentialResponse response) {
        this.response = response;
        this.body = response.getBody();
    }

    public static CredentialResponseAssert assertThat(
            final CredentialResponse response) {

        Assertions.assertThat(response)
                .as("CredentialResponse must not be null")
                .isNotNull();

        Assertions.assertThat(response.getBody())
                .as("CredentialResponse body must not be null")
                .isNotNull();

        log.debug(
                "CredentialResponse: status={}, body={}",
                response.getStatus(),
                response.getBody()
        );

        return new CredentialResponseAssert(response);
    }

    public CredentialResponseAssert hasTransactionId() {
        Assertions.assertThat(body.has("transaction_id"))
                .as("Deferred response must contain transaction_id")
                .isTrue();

        return this;
    }

    public CredentialResponseAssert hasNotTransactionId() {
        Assertions.assertThat(body.has("transaction_id"))
                .as("Deferred response must not contain transaction_id as it's issued")
                .isFalse();

        return this;
    }

    public CredentialResponseAssert hasInterval() {
        Assertions.assertThat(body.has("interval"))
                .as("Deferred response must contain interval")
                .isTrue();

        final int interval = body
                .get("interval")
                .getAsInt();

        Assertions.assertThat(interval)
                .as("interval must be a positive integer")
                .isPositive();

        return this;
    }

    public CredentialResponseAssert hasNotInterval() {
        Assertions.assertThat(body.has("interval"))
                .as("Deferred response must not contain interval as it's issued")
                .isFalse();

        return this;
    }

    public CredentialResponseAssert hasCode(final int statusCode) {
        Assertions.assertThat(this.response.getStatus())
                .as("Status code must as expected")
                .isEqualTo(statusCode);

        return this;
    }

    public CredentialResponseAssert isResponseEncrypted() {
        Assertions.assertThat(response.getRawBody())
                .as("Credential response must contain a raw body")
                .isNotNull()
                .isNotBlank();

        JWESupport.assertIsJWE(response.getRawBody());

        return this;
    }
}
