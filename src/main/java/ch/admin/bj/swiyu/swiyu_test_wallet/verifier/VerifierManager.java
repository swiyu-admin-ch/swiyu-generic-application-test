package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import ch.admin.bj.swiyu.gen.verifier.api.VerifierManagementApiApi;
import ch.admin.bj.swiyu.gen.verifier.invoker.ApiClient;
import ch.admin.bj.swiyu.gen.verifier.model.CreateVerificationManagement;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import org.springframework.web.client.RestClient;

import java.util.UUID;

public class VerifierManager {

    private final VerifierManagementApiApi managementApi;

    public VerifierManager(String issuerServiceUrl) {
        RestClient restClient = RestClient.builder().build();
        var apiClient = new ApiClient(restClient).setBasePath(issuerServiceUrl);
        managementApi = new VerifierManagementApiApi(apiClient);
    }

    public ManagementResponse createVerificationRequest(CreateVerificationManagement request) {
        ManagementResponse managementResponse = managementApi.createVerification(request);

        return managementResponse;
    }

    public ManagementResponse getVerifyState(UUID verificationId){
        return managementApi.getVerification(verificationId);
    }
}
