package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import ch.admin.bj.swiyu.gen.verifier.api.ActuatorApi;
import ch.admin.bj.swiyu.gen.verifier.api.VerifierManagementApiApi;
import ch.admin.bj.swiyu.gen.verifier.invoker.ApiClient;
import ch.admin.bj.swiyu.gen.verifier.model.*;
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

    public VerificationRequestBuilder verificationRequest() {
        return new VerificationRequestBuilder();
    }

    public class VerificationRequestBuilder {
        private final CreateVerificationManagement request;

        public VerificationRequestBuilder() {
            this.request = createDefaultRequest(true);
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
            request.responseMode(CreateVerificationManagement.ResponseModeEnum.POST_JWT);
            return this;
        }

        public VerificationRequestBuilder unencrypted() {
            request.responseMode(CreateVerificationManagement.ResponseModeEnum.POST);
            return this;
        }

        public VerificationRequestBuilder withUniversity() {
            boolean withKeyBinding = true;

            Constraint universityConstraint = new Constraint()
                    .addFieldsItem(new Field().addPathItem("$.type"))
                    .addFieldsItem(new Field().addPathItem("$.name"))
                    .addFieldsItem(new Field().addPathItem("$.average_grade"));

            InputDescriptor universityInputDescriptor = new InputDescriptor()
                    .id(UUID.randomUUID().toString())
                    .name("University Credential")
                    .putFormatItem("vc+sd-jwt", withKeyBinding ? es256Format() : es256FormatNoKeyBinding())
                    .constraints(universityConstraint);

            PresentationDefinition presentation = new PresentationDefinition()
                    .id(UUID.randomUUID().toString())
                    .name("University Presentation")
                    .purpose("Present university degree information")
                    .format(null)
                    .addInputDescriptorsItem(universityInputDescriptor);

            request.presentationDefinition(presentation);
            return this;
        }

        public VerificationRequestBuilder withDCQL() {
            DcqlCredentialMetaDto meta = new DcqlCredentialMetaDto()
                    .vctValues(List.of("http://default-issuer-url.admin.ch/oid4vci/vct/my-vct-v01"))
                    .typeValues(null);
            DcqlClaimDto claim = new DcqlClaimDto()
                    .path(List.of("type"))
                    .id(null)
                    .values(null);
            DcqlCredentialDto credential = new DcqlCredentialDto()
                    .id("VerifiableCredential")
                    .format("vc+sd-jwt")
                    .meta(meta)
                    .claims(List.of(claim))
                    .claimSets(null)
                    .requireCryptographicHolderBinding(true);

            DcqlQueryDto dcqlQuery = new DcqlQueryDto().credentials(List.of(credential));
            request.setDcqlQuery(dcqlQuery);
            return this;
        }

        public VerificationRequestBuilder withUniversityDCQL() {
            DcqlCredentialMetaDto meta = new DcqlCredentialMetaDto()
                    .vctValues(List.of("http://default-issuer-url.admin.ch/oid4vci/vct/my-vct-v01"))
                    .typeValues(List.of(List.of("string"), List.of("string"), List.of("number")));
            DcqlClaimDto claimType = new DcqlClaimDto()
                    .path(List.of("type"))
                    .id(null)
                    .values(List.of("Bachelor of Science"));
            DcqlClaimDto claimName = new DcqlClaimDto()
                    .path(List.of("name"))
                    .id(null)
                    .values(null);
            DcqlClaimDto claimAverageGrade = new DcqlClaimDto()
                    .path(List.of("average_grade"))
                    .id(null)
                    .values(null);
            DcqlCredentialDto credential = new DcqlCredentialDto()
                    .id("VerifiableCredential")
                    .format("vc+sd-jwt")
                    .meta(meta)
                    .claims(List.of(claimType, claimName, claimAverageGrade))
                    .claimSets(null)
                    .requireCryptographicHolderBinding(true);

            DcqlQueryDto dcqlQuery = new DcqlQueryDto().credentials(List.of(credential));
            request.setDcqlQuery(dcqlQuery);


            PresentationDefinition presentation = new PresentationDefinition()
                    .id(UUID.randomUUID().toString())
                    .name("string")
                    .purpose("string")
                    .format(null);

            request.presentationDefinition(presentation);

            return this;
        }

        public CreateVerificationManagement build() {
            return request;
        }

        public ManagementResponse createManagementResponse() {
            return managementApi.createVerification(request);
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

    public ManagementResponse verifyState(final VerificationStatus status) {

        managementResponse = managementApi.getVerification(managementResponse.getId());

        assertThat(managementResponse.getState()).isEqualTo(status);

        return managementResponse;
    }

    public ManagementResponse verifyState() {
        return  verifyState(VerificationStatus.SUCCESS);
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
