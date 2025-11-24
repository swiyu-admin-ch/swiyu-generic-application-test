package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import ch.admin.bj.swiyu.gen.verifier.api.ActuatorApi;
import ch.admin.bj.swiyu.gen.verifier.api.VerifierManagementApiApi;
import ch.admin.bj.swiyu.gen.verifier.invoker.ApiClient;
import ch.admin.bj.swiyu.gen.verifier.model.*;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.createDefaultRequest;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class VerifierManager {

    private final VerifierManagementApiApi managementApi;
    private ManagementResponse managementResponse;
    private final ActuatorApi actuatorApi;

    public VerifierManager(String issuerServiceUrl) {
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
}
