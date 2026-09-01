package ch.admin.bj.swiyu.swiyu_test_wallet.issuer.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.DslPart;
import au.com.dius.pact.consumer.dsl.LambdaDsl;
import ch.admin.bj.swiyu.gen.issuer.model.CreateCredentialOfferRequest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialOfferMetadataDto;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;

import java.util.List;
import java.util.Map;
import java.util.UUID;

final class IssuerManagementConsumerPactSupport {

    static final String CONSUMER = "swiyu-business-issuer-reference";
    static final String PROVIDER = "swiyu-issuer";
    static final String JSON_CONTENT_TYPE_REGEX = "^application/json(?:;\\s*charset=[^;]+)?$";
    static final String URL_REGEX = "^[a-zA-Z][a-zA-Z0-9+.-]*://\\S+$";
    static final String CREDENTIAL_STATUS_REGEX =
            "^(INIT|OFFERED|CANCELLED|IN_PROGRESS|DEFERRED|READY|ISSUED|SUSPENDED|REVOKED|REQUESTED|EXPIRED)$";

    static final UUID STATUS_LIST_ID = UUID.fromString("11111111-1111-4111-8111-111111111111");
    static final UUID MANAGEMENT_ID = UUID.fromString("22222222-2222-4222-8222-222222222222");
    static final UUID OFFER_ID = UUID.fromString("33333333-3333-4333-8333-333333333333");
    static final String STATUS_REGISTRY_URL = "https://status.example.com/api/v1/statuslist/" + STATUS_LIST_ID + ".jwt";
    static final String OFFER_DEEPLINK = "swiyu://?credential_offer=example-" + OFFER_ID;

    private IssuerManagementConsumerPactSupport() {
    }

    static BusinessIssuer buildBusinessIssuer(final MockServer mockServer) {
        return new BusinessIssuer(IssuerConfig.builder()
                .issuerServiceUrl(mockServer.getUrl())
                .build());
    }

    static CreateCredentialOfferRequest credentialOfferRequest(final boolean deferred) {
        return new CreateCredentialOfferRequest()
                .metadataCredentialSupportedId(List.of("test"))
                .credentialSubjectData(Map.of(
                        "firstName", "John",
                        "lastName", "Doe",
                        "dateOfBirth", "2000-01-01"))
                .credentialMetadata(new CredentialOfferMetadataDto().deferred(deferred))
                .offerValiditySeconds(86400);
    }

    static DslPart credentialCreationRequestBody(final boolean deferred) {
        return LambdaDsl.newJsonBody(body -> body
                .array("metadata_credential_supported_id", ids -> ids.stringValue("test"))
                .object("credential_subject_data", subject -> subject
                        .stringValue("firstName", "John")
                        .stringValue("lastName", "Doe")
                        .stringValue("dateOfBirth", "2000-01-01"))
                .object("credential_metadata", metadata -> metadata
                        .booleanValue("deferred", deferred)
                        .nullValue("vct_metadata_uri")
                        .nullValue("vct_metadata_uri#integrity"))
                .numberValue("offer_validity_seconds", 86400)
                .nullValue("deferred_offer_validity_seconds")
                .nullValue("credential_valid_until")
                .nullValue("credential_valid_from")
                .array("status_lists")
                .nullValue("configuration_override")).build();
    }

    static DslPart credentialCreationResponseBody() {
        return LambdaDsl.newJsonBody(body -> body
                .uuid("management_id", MANAGEMENT_ID)
                .uuid("offer_id", OFFER_ID)
                .stringMatcher("offer_deeplink", URL_REGEX, OFFER_DEEPLINK)).build();
    }

    static DslPart credentialManagementResponseBody() {
        return LambdaDsl.newJsonBody(body -> body
                .uuid("id", MANAGEMENT_ID)
                .stringMatcher("status", CREDENTIAL_STATUS_REGEX, "OFFERED")
                .integerType("renewal_request_count", 0)
                .integerType("renewal_response_count", 0)
                .minArrayLike("credential_offers", 1, offer -> offer
                        .stringMatcher("status", CREDENTIAL_STATUS_REGEX, "OFFERED")
                        .array("metadata_credential_supported_id", ids -> ids.stringType("test"))
                        .object("credential_metadata", metadata -> metadata.booleanType("deferred", false))
                        .integerType("offer_expiration_timestamp", 1893456000)
                        .stringMatcher("offer_deeplink", URL_REGEX, OFFER_DEEPLINK))).build();
    }

    static DslPart credentialOfferResponseBody(final String status) {
        return LambdaDsl.newJsonBody(body -> body
                .stringMatcher("status", CREDENTIAL_STATUS_REGEX, status)
                .array("metadata_credential_supported_id", ids -> ids.stringType("test"))
                .object("credential_metadata", metadata -> metadata.booleanType("deferred", "DEFERRED".equals(status)))
                .integerType("offer_expiration_timestamp", 1893456000)
                .stringMatcher("offer_deeplink", URL_REGEX, OFFER_DEEPLINK)).build();
    }

    static DslPart statusResponseBody(final String status) {
        return LambdaDsl.newJsonBody(body -> body
                .stringMatcher("status", CREDENTIAL_STATUS_REGEX, status))
                .build();
    }

    static DslPart updateStatusResponseBody(final String status) {
        return LambdaDsl.newJsonBody(body -> body
                .uuid("id", MANAGEMENT_ID)
                .stringMatcher("status", CREDENTIAL_STATUS_REGEX, status))
                .build();
    }
}
