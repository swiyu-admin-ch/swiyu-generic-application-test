package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import ch.admin.bj.swiyu.gen.verifier.api.VerifierManagementApiApi;
import ch.admin.bj.swiyu.gen.verifier.invoker.ApiClient;
import ch.admin.bj.swiyu.gen.verifier.model.CreateVerificationManagement;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.createDefaultRequest;

public class VerifierManager {

    private ManagementResponse managementResponse;

    private final VerifierManagementApiApi managementApi;

    public VerifierManager(String issuerServiceUrl) {
        RestClient restClient = RestClient.builder().build();
        var apiClient = new ApiClient(restClient).setBasePath(issuerServiceUrl);
        managementApi = new VerifierManagementApiApi(apiClient);
    }

    public String createVerificationRequest() {
        CreateVerificationManagement request = createDefaultRequest(true);

        return createVerificationRequest(request).getVerificationDeeplink();
    }

    public ManagementResponse createVerificationRequest(CreateVerificationManagement request) {
        managementResponse =  managementApi.createVerification(request);

        return managementResponse;
    }

    public ManagementResponse verifyState() {

        managementResponse = managementApi.getVerification(managementResponse.getId());

        assertThat(managementResponse.getState()).isEqualTo(VerificationStatus.SUCCESS);

        return managementResponse;
    }
}
