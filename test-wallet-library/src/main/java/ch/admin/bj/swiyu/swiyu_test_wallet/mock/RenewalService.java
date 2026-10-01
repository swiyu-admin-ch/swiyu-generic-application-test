package ch.admin.bj.swiyu.swiyu_test_wallet.mock;

import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.TestSupportException;
import org.mockserver.client.MockServerClient;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;

/**
 * The Business Issuer's renewal endpoint the Credential Issuer calls when a Wallet renews a Credential: answers with the
 * subject data and validity of the renewed Credential and the status list it must use.
 */
final class RenewalService {

    private final StatusRegistry statusRegistry;

    RenewalService(final StatusRegistry statusRegistry) {
        this.statusRegistry = statusRegistry;
    }

    void registerRoutes(final MockServerClient mockServerClient) {
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

        mockServerClient
                .when(request().withMethod("POST").withPath("/renewal"))
                .respond(httpRequest -> {
                    try {
                        return response()
                                .withStatusCode(200)
                                .withHeader(CONTENT_TYPE, "application/json")
                                .withBody(new ObjectMapper().writeValueAsString(
                                        Map.of(
                                                "metadata_credential_supported_id", List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT),
                                                "credential_subject_data", CredentialSubjectFixtures.completeEmployeeProfile(),
                                                "credential_metadata", Map.of("vct#integrity", "sha256-0000000000000000000000000000000000000000000="),
                                                "credential_valid_from", validFrom,
                                                "credential_valid_until", validUntil,
                                                "status_lists", List.of(statusRegistry.currentRenewalStatusList(httpRequest)))));
                    } catch (JacksonException e) {
                        throw new TestSupportException("Cannot parse correctly data");
                    }
                });
    }
}
