package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import ch.admin.bj.swiyu.gen.issuer.api.ActuatorApi;
import ch.admin.bj.swiyu.gen.issuer.api.CredentialApiApi;
import ch.admin.bj.swiyu.gen.issuer.api.StatusListApiApi;
import ch.admin.bj.swiyu.gen.issuer.invoker.ApiClient;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialOfferMetadataDto;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialOfferRequest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.gen.issuer.model.StatusListCreate;
import ch.admin.bj.swiyu.gen.issuer.model.StatusListCreateConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerConfig;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class BusinessIssuer {

    private final CredentialApiApi credentialApi;
    private final StatusListApiApi statusListApi;
    private final ActuatorApi actuatorApi;

    private StatusList statusList;

    public BusinessIssuer(IssuerConfig issuerConfig) {
        RestClient restClient = RestClient.builder().build();
        var apiClient = new ApiClient(restClient).setBasePath(issuerConfig.getIssuerServiceUrl());
        credentialApi = new CredentialApiApi(apiClient);
        statusListApi = new StatusListApiApi(apiClient);
        actuatorApi = new ActuatorApi(apiClient);
    }

    public StatusList createStatusList(int size, int bits) {
        ch.admin.bj.swiyu.gen.issuer.model.StatusListCreate statusListCreate = new ch.admin.bj.swiyu.gen.issuer.model.StatusListCreate();
        statusListCreate.setType(StatusListCreate.TypeEnum.TOKEN_STATUS_LIST);
        statusListCreate.setMaxLength(size);
        statusListCreate.setConfig(new StatusListCreateConfig().bits(bits));

        statusList = statusListApi.createStatusList(statusListCreate);

        return statusListApi.createStatusList(statusListCreate);
    }

    public CredentialWithDeeplinkResponse createCredentialOffer(String supportedMetadataId) {
        CredentialOfferMetadataDto credentialOfferMetadataDto = new CredentialOfferMetadataDto();
        credentialOfferMetadataDto.setDeferred(false);

        var offer = createCredentialOfferRequest(supportedMetadataId, credentialOfferMetadataDto);

        return createCredential(offer);
    }

    public CredentialWithDeeplinkResponse createDeferredCredentialOffer(String supportedMetadataId) {
        CredentialOfferMetadataDto credentialOfferMetadataDto = new CredentialOfferMetadataDto();
        credentialOfferMetadataDto.setDeferred(true);

        var offer = createCredentialOfferRequest(supportedMetadataId, credentialOfferMetadataDto);

        return createCredential(offer);
    }

    public CredentialWithDeeplinkResponse createCredential(CredentialOfferRequest offer) {
        return credentialApi.createCredential1(offer);
    }

    public void updateState(UUID id,
                            ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType newState) {
        updateVcStatus(id, newState);
    }

    public void updateVcStatus(UUID id,
                               ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType newState) {
        credentialApi.updateCredentialStatus(id, newState);
    }

    public Map<String, Object> health() {
        return (Map<String, Object>) actuatorApi.health();
    }

    private CredentialOfferRequest createCredentialOfferRequest(String supportedMetadataId, CredentialOfferMetadataDto credentialMetadata) {
        CredentialOfferRequest offer = new CredentialOfferRequest();
        offer.setCredentialSubjectData(CredentialOffer.defaultSubjectData());
        offer.setStatusLists(List.of(statusList.getStatusRegistryUrl()));
        offer.setCredentialMetadata(credentialMetadata);
        offer.setMetadataCredentialSupportedId(List.of(supportedMetadataId));
        offer.setOfferValiditySeconds(86400); // 24h
        return offer;
    }
}
