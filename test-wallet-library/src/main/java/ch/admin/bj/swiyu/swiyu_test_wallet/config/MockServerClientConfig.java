package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.TestSupportException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.experimental.UtilityClass;

import org.apache.http.protocol.HTTP;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpStatusCode;
import org.mockserver.model.MediaType;
import org.testcontainers.containers.MockServerContainer;

import java.text.ParseException;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

@UtilityClass
public class MockServerClientConfig {

    @SuppressWarnings("java:S1075") // Constant URI is intentional: used only in test/support context
    public static final String ISSUER_CALLBACK_PATH = "/callbacks/issuer";
    @SuppressWarnings("java:S1075") // Constant URI is intentional: used only in test/support context
    public static final String VERIFIER_CALLBACK_PATH = "/callbacks/issuer";
    private static final String MOCKSERVER_HOST = "mockserver:1080";
    private static final String STATUSLIST_URI_PATTERN = "https://" + MOCKSERVER_HOST + "/api/v1/statuslist/%s.jwt";

    private static boolean shouldReturnRevokedStatusList = false;

    public static MockServerClient createMockServerClient(MockServerContainer mockServer,
            IssuerConfig issuerConfig) {

        final String validFrom = LocalDate.now(ZoneOffset.UTC)
                .minusDays(7)
                .atStartOfDay(ZoneOffset.UTC)
                .toInstant()
                .toString();

        final String validUntil = LocalDate.now(ZoneOffset.UTC)
                .plusDays(7)
                .atStartOfDay(ZoneOffset.UTC)
                .toInstant()
                .toString();
        MockServerClient mockServerClient = new MockServerClient(
                mockServer.getHost(),
                mockServer.getServerPort());

        // Register expectations
        mockServerClient.when(request()
                .withMethod("GET")
                .withPath("/api/v1/statuslist/[a-zA-Z0-9-_]+\\.jwt"))
                .respond(
                        httpRequest -> response()
                                .withHeader(HTTP.CONTENT_TYPE,
                                        "application/statuslist+jwt")
                                .withStatusCode(HttpStatusCode.OK_200.code())
                                .withBody(getStatusListJwt(httpRequest, issuerConfig)));
        mockServerClient.when(
                request()
                        .withMethod("POST")
                        .withPath("/api/v1/status/business-entities/{businessId}/status-list-entries/")
                        .withPathParameter("businessId", ".*"))
                .respond(httpRequest -> {
                    var id = UUID.randomUUID();
                    var payload = "{\"id\": \"%s\", \"statusRegistryUrl\": \"%s\"}"
                            .formatted(id, STATUSLIST_URI_PATTERN.formatted(id));
                    return response()
                            .withStatusCode(200)
                            .withHeader(HTTP.CONTENT_TYPE, "application/json")
                            .withBody(payload);
                });
        mockServerClient.when(request().withMethod("PUT").withPath(
                "/api/v1/status/business-entities/{businessId}/status-list-entries/{statusListId}")
                .withPathParameter("businessId", ".*").withPathParameter("statusListId", ".*"))
                .respond(response().withStatusCode(202));
        mockServerClient.when(request().withMethod("GET").withPath("/api/v1/did/[a-zA-Z0-9-_]+\\/did.jsonl"))
                .respond(
                        httpRequest -> response()
                                .withStatusCode(200)
                                .withHeader(HTTP.CONTENT_TYPE, "application/jsonl+json")
                                .withBody(issuerConfig.getIssuerDidLog()));
        mockServerClient.when(request().withMethod("POST").withPath("/openid-connect/token"))
                .respond(response().withStatusCode(200).withContentType(MediaType.APPLICATION_JSON)
                        .withBody("{\"access_token\": \"access_token\", \"refresh_token\": \"refresh_token\"}"));

        mockServerClient.when(request().withMethod("POST").withPath(ISSUER_CALLBACK_PATH))
                .respond(response().withStatusCode(204).withContentType(MediaType.APPLICATION_JSON));

        mockServerClient.when(request().withMethod("POST").withPath(VERIFIER_CALLBACK_PATH))
                .respond(response().withStatusCode(204).withContentType(MediaType.APPLICATION_JSON));

        try {
            mockServerClient
                    .when(
                            request()
                                    .withMethod("POST")
                                    .withPath("/renewal"))
                    .respond(
                            response()
                                    .withStatusCode(200)
                                    .withHeader(HTTP.CONTENT_TYPE, "application/json")
                                    .withBody(new ObjectMapper().writeValueAsString(
                                            Map.of(
                                                    "metadata_credential_supported_id", List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT),
                                                    "credential_subject_data", CredentialSubjectFixtures.completeEmployeeProfile(),
                                                    "credential_metadata", Map.of("vct#integrity","sha256-0000000000000000000000000000000000000000000="),
                                                    "credential_valid_from", validFrom,
                                                    "credential_valid_until", validUntil,
                                                    "status_lists", List.of()))));
        } catch (JsonProcessingException e) {
            throw new TestSupportException("Cannot parse correctly data");
        }

        return mockServerClient;
    }

    private static String getStatusListJwt(HttpRequest httpRequest, IssuerConfig issuerConfig)
            throws JOSEException, ParseException {

        JWK jwk = JWK.parseFromPEMEncodedObjects(issuerConfig.getIssuerAssertKeyPemString());

        JWSSigner signer = new ECDSASigner(jwk.toECKey());

        String statusBits = shouldReturnRevokedStatusList ?
                "eNrtwQEBAAAAgiD_r25IQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHwYYagAAE=" :
                "eNrtwQEBAAAAgiD_r25IQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHwYYagAAQ";

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(httpRequest.getPath().getValue())
                .issuer(issuerConfig.getIssuerDid())
                .claim("status_list", Map.of(
                        "bits", "2",
                        "lst", statusBits))
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .keyID(issuerConfig.getIssuerAssertKeyId())
                        .type(new JOSEObjectType("statuslist+jwt"))
                        .build(),
                claimsSet);

        signedJWT.sign(signer);

        String s = signedJWT.serialize();

        return SignedJWT.parse(s).serialize();
    }

    public static void toggleRevokedStatusList() {
        shouldReturnRevokedStatusList = !shouldReturnRevokedStatusList;
    }

    public static void setRevokedStatusList(boolean revoked) {
        shouldReturnRevokedStatusList = revoked;
    }

    public static void resetRevokedStatusList() {
        shouldReturnRevokedStatusList = false;
    }
}

