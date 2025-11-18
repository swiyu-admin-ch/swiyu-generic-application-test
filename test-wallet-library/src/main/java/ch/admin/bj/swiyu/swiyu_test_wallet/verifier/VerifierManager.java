package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import ch.admin.bj.swiyu.gen.verifier.api.ActuatorApi;
import ch.admin.bj.swiyu.gen.verifier.api.VerifierManagementApiApi;
import ch.admin.bj.swiyu.gen.verifier.invoker.ApiClient;
import ch.admin.bj.swiyu.gen.verifier.model.CreateVerificationManagement;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlClaimDto;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlCredentialDto;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlCredentialMetaDto;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlQueryDto;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
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

    public String createVerificationRequest() {
        return createVerificationRequest(false);
    }

    public String createVerificationRequest(final boolean encrypted) {
        CreateVerificationManagement request = createDefaultRequest(true, encrypted);

        return createVerificationRequest(request).getVerificationDeeplink();
    }

    public String createDCQLVerificationRequest(final boolean encrypted) {
        CreateVerificationManagement request = createDefaultRequest(true, encrypted);

        DcqlCredentialMetaDto meta = new DcqlCredentialMetaDto().vctValues(List.of("http://default-issuer-url.admin.ch/oid4vci/vct/my-vct-v01")).typeValues(null);
        DcqlClaimDto claim = new DcqlClaimDto().path(List.of("type")).id(null).values(null);
        DcqlCredentialDto credential = new DcqlCredentialDto().id("VerifiableCredential").format("vc+sd-jwt").meta(meta).claims(List.of(claim)).claimSets(null).requireCryptographicHolderBinding(true);

        DcqlQueryDto dcqlQuery = new DcqlQueryDto().credentials(List.of(credential));

        request.setDcqlQuery(dcqlQuery);

        return createVerificationRequest(request).getVerificationDeeplink();
    }

    public String createDCQLVerificationRequest() {
        return createDCQLVerificationRequest(false);
    }

    public CreateVerificationManagement createVerificationRequestObject() {
        CreateVerificationManagement request = createDefaultRequest(true, false);

        return request;
    }

    public CreateVerificationManagement createDCQLVerificationRequestObject() {
        CreateVerificationManagement request = createDefaultRequest(true, false);

        DcqlCredentialMetaDto meta = new DcqlCredentialMetaDto().vctValues(List.of("http://default-issuer-url.admin.ch/oid4vci/vct/my-vct-v01")).typeValues(null);
        DcqlClaimDto claim = new DcqlClaimDto().path(List.of("type")).id(null).values(null);
        DcqlCredentialDto credential = new DcqlCredentialDto().id("VerifiableCredential").format("vc+sd-jwt").meta(meta).claims(List.of(claim)).claimSets(null).requireCryptographicHolderBinding(true);

        DcqlQueryDto dcqlQuery = new DcqlQueryDto().credentials(List.of(credential));

        request.setDcqlQuery(dcqlQuery);

        return request;
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
