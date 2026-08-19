package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import ch.admin.bj.swiyu.gen.verifier.api.ActuatorApi;
import ch.admin.bj.swiyu.gen.verifier.api.VerifierManagementApiApi;
import ch.admin.bj.swiyu.gen.verifier.invoker.ApiClient;
import ch.admin.bj.swiyu.gen.verifier.model.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.support.TestPresentationDefinitions;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.HttpTraceInterceptor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.*;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class VerifierManager {

    private VerifierManagementApiApi managementApi;
    private ManagementResponse managementResponse;
    private ActuatorApi actuatorApi;
    private String issuerServiceUrl;
    private String bearerToken;
    private HttpTraceInterceptor traceInterceptor;

    public VerifierManager(String issuerServiceUrl) {
        this.issuerServiceUrl = issuerServiceUrl;
        configureApis();
    }

    public void useBearerToken(String token) {
        bearerToken = token;
        configureApis();
    }

    private void applyStoredBearerToken(ApiClient apiClient) {
        if (bearerToken != null && !bearerToken.isBlank()) {
            apiClient.addDefaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken);
        }
    }

    public VerificationRequestBuilder verificationRequest(final boolean withKeyBinding) {
        return new VerificationRequestBuilder(withKeyBinding);
    }

    public VerificationRequestBuilder verificationRequest() {
        return new VerificationRequestBuilder(true);
    }

    public class VerificationRequestBuilder {
        private final CreateVerificationManagement request;

        public VerificationRequestBuilder(final boolean withKeyBinding) {
            this.request = createDefaultRequest(withKeyBinding);
        }

        public CreateVerificationManagement getRequest() {
            return request;
        }

        public VerificationRequestBuilder acceptedIssuerDids(List<String> dids) {
            request.acceptedIssuerDids(dids);
            return this;
        }

        public VerificationRequestBuilder trustAnchors(List<TrustAnchor> trustAnchors) {
            request.trustAnchors(trustAnchors);
            return this;
        }

        public VerificationRequestBuilder acceptedIssuerDid(final String did) {
            request.addAcceptedIssuerDidsItem(did);
            return this;
        }

        public VerificationRequestBuilder trustAnchor(TrustAnchor trustAnchor) {
            request.addTrustAnchorsItem(trustAnchor);
            return this;
        }

        public VerificationRequestBuilder encrypted() {
            request.responseMode(ResponseModeType.DIRECT_POST_JWT);
            return this;
        }

        public VerificationRequestBuilder unencrypted() {
            request.responseMode(ResponseModeType.DIRECT_POST);
            return this;
        }

        public VerificationRequestBuilder dcqlQuery(final DcqlQueryDto dcqlQuery) {
            request.dcqlQuery(dcqlQuery);
            return this;
        }

        public VerificationRequestBuilder verificationPurpose(VerificationPurpose verificationPurpose) {
            request.verificationPurpose(verificationPurpose);
            return this;
        }

        public VerificationRequestBuilder redirectUri(URI redirectUri) {
            request.redirectUri(redirectUri);
            return this;
        }

        public VerificationRequestBuilder configurationOverride(ConfigurationOverrideDto configurationOverride) {
            request.configurationOverride(configurationOverride);
            return this;
        }

        private VerificationRequestBuilder jwtSecuredAuthorizationRequest(boolean jwtSecuredAuthorizationRequest) {
            request.jwtSecuredAuthorizationRequest(jwtSecuredAuthorizationRequest);
            return this;
        }

        public VerificationRequestBuilder jwtSecure() {
            return jwtSecuredAuthorizationRequest(true);
        }

        public VerificationRequestBuilder jwtUnsecure() {
            return jwtSecuredAuthorizationRequest(false);
        }

        public VerificationRequestBuilder withUniversity() {
            return withUniversityDCQL();
        }

        public VerificationRequestBuilder withDCQL() {
            return this.withDCQL(List.of(dcqlClaim("name")));
        }

        public VerificationRequestBuilder withDCQL(final List<DcqlClaimDto> claims) {
            request.setDcqlQuery(defaultDcqlQuery(claims, true));
            return this;
        }

        public VerificationRequestBuilder withUniversityDCQL(final boolean holderBinding) {
            request.setDcqlQuery(TestPresentationDefinitions.universityPresentationDCQL(holderBinding));
            return this;
        }

        public VerificationRequestBuilder withUniversityDCQL() {
            withUniversityDCQL(true);
            return this;
        }

        public CreateVerificationManagement build() {
            return request;
        }

        public ManagementResponse createManagementResponse() {
            managementResponse = managementApi.createVerification(request);
            return managementResponse;
        }

        public String create() {
            managementResponse = createManagementResponse();
            return managementResponse.getVerificationDeeplink();
        }
    }

    public ManagementResponse createVerificationRequest(CreateVerificationManagement request) {
        managementResponse = managementApi.createVerification(request);

        return managementResponse;
    }

    public Map<String, Object> health() {
        return (Map<String, Object>) actuatorApi.health();
    }

    public ManagementResponse verifyState(final UUID verificationId, final VerificationStatus status, final String assertMessage) {

        managementResponse = managementApi.getVerification(verificationId, null);

        assertThat(managementResponse.getState()).as(assertMessage).isEqualTo(status);

        return managementResponse;
    }

    public ManagementResponse verifyHasNotState(final UUID verificationId, final VerificationStatus status, final String assertMessage) {

        managementResponse = managementApi.getVerification(verificationId, null);

        assertThat(managementResponse.getState()).as(assertMessage).isNotEqualTo(status);

        return managementResponse;
    }

    public ManagementResponse verifyState(final UUID verificationId, final VerificationStatus status) {
        return verifyState(verificationId, status, null);
    }

    public ManagementResponse verifyState(final VerificationStatus status) {
        return verifyState(managementResponse.getId(), status);
    }

    public ManagementResponse getVerificationById(UUID id) {
        return getVerificationById(id, null);
    }

    public ManagementResponse getVerificationById(UUID id, UUID responseCode) {
        return managementApi.getVerification(id, responseCode);
    }

    public ManagementResponse verifyState(final UUID verificationId) {
        return verifyState(verificationId, VerificationStatus.SUCCESS);
    }

    public ManagementResponse verifyState() {
        return verifyState(VerificationStatus.SUCCESS);
    }

    public void intercept(HttpTraceInterceptor interceptor) {
        traceInterceptor = interceptor;
        configureApis();
    }

    private void configureApis() {
        var builder = RestClient.builder();
        if (traceInterceptor != null) {
            builder = builder.requestFactory(
                            new BufferingClientHttpRequestFactory(new SimpleClientHttpRequestFactory()))
                    .requestInterceptor(traceInterceptor);
        }
        if (bearerToken != null && !bearerToken.isBlank()) {
            builder = builder.defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken);
        }
        RestClient restClient = builder.build();
        var apiClient = new ApiClient(restClient).setBasePath(issuerServiceUrl);
        applyStoredBearerToken(apiClient);
        managementApi = new VerifierManagementApiApi(apiClient);
        actuatorApi = new ActuatorApi(apiClient);
    }
}
