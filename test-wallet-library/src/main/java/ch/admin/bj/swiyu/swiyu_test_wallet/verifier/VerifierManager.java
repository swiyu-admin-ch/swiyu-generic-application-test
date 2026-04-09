package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import ch.admin.bj.swiyu.gen.verifier.api.ActuatorApi;
import ch.admin.bj.swiyu.gen.verifier.api.VerifierManagementApiApi;
import ch.admin.bj.swiyu.gen.verifier.invoker.ApiClient;
import ch.admin.bj.swiyu.gen.verifier.model.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.support.TestPresentationDefinitions;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.HttpTraceInterceptor;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

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

    public VerifierManager(String issuerServiceUrl) {
        this.issuerServiceUrl = issuerServiceUrl;
        RestClient restClient = RestClient.builder().build();
        var apiClient = new ApiClient(restClient).setBasePath(issuerServiceUrl);
        managementApi = new VerifierManagementApiApi(apiClient);
        actuatorApi = new ActuatorApi(apiClient);
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

        public VerificationRequestBuilder presentationDefinition(PresentationDefinition presentationDefinition) {
            request.presentationDefinition(presentationDefinition);
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

        public VerificationRequestBuilder presentation(final PresentationDefinition presentation) {
            request.presentationDefinition(presentation);
            return this;
        }

        public VerificationRequestBuilder withUniversity() {
            request.presentationDefinition(TestPresentationDefinitions.universityPresentation());
            return this;
        }

        public VerificationRequestBuilder withDCQL() {
            final List<DcqlClaimDto> claims = List.of(
                new DcqlClaimDto()
                    .path(List.of("name"))
                    .id(null)
                    .values(null)
                );
            return this.withDCQL(claims);
        }

        public VerificationRequestBuilder withDCQL(final List<DcqlClaimDto> claims) {
            DcqlCredentialMetaDto meta = new DcqlCredentialMetaDto()
                    .vctValues(List.of("http://default-issuer-url.admin.ch/oid4vci/vct/my-vct-v01"))
                    .typeValues(null);
            DcqlCredentialDto credential = new DcqlCredentialDto()
                    .id("VerifiableCredential")
                    .format("vc+sd-jwt")
                    .meta(meta)
                    .claims(claims)
                    .claimSets(null)
                    .requireCryptographicHolderBinding(true);

            DcqlQueryDto dcqlQuery = new DcqlQueryDto().credentials(List.of(credential));
            request.setDcqlQuery(dcqlQuery);
            return this;
        }

        public VerificationRequestBuilder withUniversityDCQL(final boolean holderBinding) {
            request.setDcqlQuery(TestPresentationDefinitions.universityPresentationDCQL(holderBinding));

            final PresentationDefinition presentation = new PresentationDefinition()
                    .id(UUID.randomUUID().toString())
                    .name("DCQL Example")
                    .purpose("Test purpose")
                    .format(null);
            request.presentationDefinition(presentation);
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

        managementResponse = managementApi.getVerification(verificationId);

        assertThat(managementResponse.getState()).as(assertMessage).isEqualTo(status);

        return managementResponse;
    }

    public ManagementResponse verifyState(final UUID verificationId, final VerificationStatus status) {
        return verifyState(verificationId, status, null);
    }

    public ManagementResponse verifyState(final VerificationStatus status) {
        return verifyState(managementResponse.getId(), status);
    }

    public ManagementResponse getVerificationById(UUID id) {
        return managementApi.getVerification(id);
    }

    public ManagementResponse verifyState(final UUID verificationId) {
        return verifyState(verificationId, VerificationStatus.SUCCESS);
    }

    public ManagementResponse verifyState() {
        return verifyState(VerificationStatus.SUCCESS);
    }

    public void intercept(HttpTraceInterceptor interceptor) {
        var builder = RestClient.builder();
        builder = builder.requestFactory(
                        new BufferingClientHttpRequestFactory(new SimpleClientHttpRequestFactory()))
                .requestInterceptor(interceptor);
        RestClient restClient = builder.build();
        var apiClient = new ApiClient(restClient).setBasePath(issuerServiceUrl);
        managementApi = new VerifierManagementApiApi(apiClient);
        actuatorApi = new ActuatorApi(apiClient);
    }
}
