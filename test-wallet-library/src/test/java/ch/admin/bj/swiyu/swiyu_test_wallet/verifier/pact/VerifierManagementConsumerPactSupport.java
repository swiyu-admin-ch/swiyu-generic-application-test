package ch.admin.bj.swiyu.swiyu_test_wallet.verifier.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.DslPart;
import au.com.dius.pact.consumer.dsl.LambdaDsl;
import ch.admin.bj.swiyu.gen.verifier.model.CreateVerificationManagement;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.util.List;
import java.util.Map;
import java.util.UUID;

final class VerifierManagementConsumerPactSupport {

    static final String CONSUMER = "swiyu-business-verifier-reference";
    static final String PROVIDER = "swiyu-verifier";
    static final String JSON_CONTENT_TYPE_REGEX = "^application/json(?:;\\s*charset=[^;]+)?$";
    static final String URI_REGEX = "^[a-zA-Z][a-zA-Z0-9+.-]*://\\S+$";
    static final String VERIFICATION_STATUS_REGEX = "^(PENDING|SUCCESS|FAILED)$";

    static final UUID VERIFICATION_ID = UUID.fromString("44444444-4444-4444-8444-444444444444");
    static final UUID RESPONSE_CODE = UUID.fromString("55555555-5555-4555-8555-555555555555");
    static final UUID WRONG_RESPONSE_CODE = UUID.fromString("66666666-6666-4666-8666-666666666666");
    static final String VERIFICATION_URL = "https://verifier.example.com/oid4vp/api/request-object/" + VERIFICATION_ID;
    static final String VERIFICATION_DEEPLINK = "swiyu-verify://?client_id=example&request_uri=" + VERIFICATION_URL;

    private VerifierManagementConsumerPactSupport() {
    }

    static VerifierManager buildVerifierManager(final MockServer mockServer) {
        return new VerifierManager(mockServer.getUrl());
    }

    static CreateVerificationManagement validVerificationRequest() {
        final var request = VerificationRequests.createDefaultRequest(true);
        request.setAcceptedIssuerDids(List.of("did:example:issuer"));
        request.getDcqlQuery().getCredentials().getFirst().getMeta()
                .setVctValues(List.of("https://issuer.example.com/vct/test"));
        return request;
    }

    static String validVerificationRequestBody() {
        try {
            return new ObjectMapper().writeValueAsString(validVerificationRequest());
        } catch (JacksonException exception) {
            throw new IllegalStateException("Could not serialize valid verification fixture", exception);
        }
    }

    static String invalidVerificationRequestBody() {
        try {
            return new ObjectMapper().writeValueAsString(new CreateVerificationManagement());
        } catch (JacksonException exception) {
            throw new IllegalStateException("Could not serialize invalid verification fixture", exception);
        }
    }

    static Map<String, Object> verificationStateParameters() {
        return Map.of(
                "verificationId", VERIFICATION_ID.toString(),
                "responseCode", RESPONSE_CODE.toString());
    }

    static DslPart verificationResponseBody(final String state, final boolean withWalletResponse) {
        return LambdaDsl.newJsonBody(body -> {
            body.uuid("id", VERIFICATION_ID)
                    .stringType("request_nonce", "request-nonce-example")
                    .stringMatcher("state", VERIFICATION_STATUS_REGEX, state)
                    .stringMatcher("verification_url", URI_REGEX, VERIFICATION_URL)
                    .stringMatcher("verification_deeplink", URI_REGEX, VERIFICATION_DEEPLINK);
            if (withWalletResponse) {
                body.object("wallet_response", wallet -> wallet
                        .object("credential_subject_data", credentials -> credentials
                                .object("VerifiableCredential", credential -> credential
                                        .stringType("given_name", "John")
                                        .stringType("family_name", "Doe"))));
            }
        }).build();
    }
}
