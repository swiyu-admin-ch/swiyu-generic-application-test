package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import ch.admin.bj.swiyu.gen.issuer.api.ActuatorApi;
import ch.admin.bj.swiyu.gen.issuer.api.CredentialApiApi;
import ch.admin.bj.swiyu.gen.issuer.api.StatusListApiApi;
import ch.admin.bj.swiyu.gen.issuer.invoker.ApiClient;
import ch.admin.bj.swiyu.gen.issuer.model.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.HttpTraceInterceptor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jdk.jfr.ContentType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import static io.netty.handler.codec.http.HttpHeaders.Values.APPLICATION_JSON;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@Slf4j
public class BusinessIssuer {

    private CredentialApiApi credentialApi;
    private StatusListApiApi statusListApi;
    private ActuatorApi actuatorApi;

    private StatusList statusList;
    private IssuerConfig issuerConfig;
    private final List<ClientHttpRequestInterceptor> interceptors = new ArrayList<>();

    public BusinessIssuer(IssuerConfig issuerConfig) {
        this.issuerConfig = issuerConfig;
        RestClient restClient = RestClient.builder().build();
        var apiClient = new ApiClient(restClient).setBasePath(issuerConfig.getIssuerServiceUrl());
        credentialApi = new CredentialApiApi(apiClient);
        statusListApi = new StatusListApiApi(apiClient);
        actuatorApi = new ActuatorApi(apiClient);
    }

    private void applyJwt(String jwt) {
        ApiClient apiClient = statusListApi.getApiClient();
        apiClient.addDefaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + jwt);
    }

    public StatusList createStatusList(int size, int bits) {
        ch.admin.bj.swiyu.gen.issuer.model.StatusListCreate statusListCreate = new ch.admin.bj.swiyu.gen.issuer.model.StatusListCreate();
        statusListCreate.setType(StatusListCreate.TypeEnum.TOKEN_STATUS_LIST);
        statusListCreate.setMaxLength(size);
        statusListCreate.setConfig(new StatusListCreateConfig().bits(bits));

        statusList = statusListApi.createStatusList(statusListCreate);

        return statusList;
    }

    public StatusList createStatusList(int size, int bits, String jwt) {
        applyJwt(jwt);

        ch.admin.bj.swiyu.gen.issuer.model.StatusListCreate statusListCreate = new ch.admin.bj.swiyu.gen.issuer.model.StatusListCreate();
        statusListCreate.setType(StatusListCreate.TypeEnum.TOKEN_STATUS_LIST);
        statusListCreate.setMaxLength(size);
        statusListCreate.setConfig(new StatusListCreateConfig().bits(bits));

        statusList = statusListApi.createStatusList(statusListCreate);

        return statusList;
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

    public CredentialInfoResponse getCredentialById(UUID id) {
        return credentialApi.getCredentialInformation(id);
    }

    public StatusResponse getStatusById(UUID id) {
        return credentialApi.getCredentialStatus(id);
    }

    public void verifyStatus(final UUID id, final CredentialStatusType credentialStatusType) {
        final StatusResponse response = getStatusById(id);
        assertThat(response.getStatus()).isEqualTo(credentialStatusType);
    }

    public UpdateStatusResponse updateCredentialForDeferredFlowRequestCreation(UUID id, Map<String, Object> body) {
        return credentialApi.updateCredentialForDeferredFlow(id, body);
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

    public StatusList createStatusListWithSignedJwt(int size, int bits, PrivateKey privateKey, String keyId) {
        String jwt;
        try {
            jwt = createSignedJwtWithEcKey(size, bits, privateKey, keyId);
        } catch (JsonProcessingException | JOSEException e) {
            throw new RuntimeException(e);
        }

        final RestClient restClient = RestClient.builder().build();
        final String url = issuerConfig.getIssuerServiceUrl() + "/management/api/status-list";
        final StatusList response = restClient.post()
                .uri(url)
                .header(HttpHeaders.CONTENT_TYPE, APPLICATION_JSON)
                .body(jwt)
                .retrieve()
                .body(StatusList.class);
        statusList = response;
        return statusList;
    }

    private String createSignedJwtWithEcKey(int size, int bits, PrivateKey privateKey, String keyId) throws JsonProcessingException, JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(keyId)
                .build();

        ObjectMapper mapper = new ObjectMapper();

        StatusListCreate statusListCreate = new StatusListCreate();
        statusListCreate.setType(StatusListCreate.TypeEnum.TOKEN_STATUS_LIST);
        statusListCreate.setMaxLength(size);
        statusListCreate.setConfig(new StatusListCreateConfig().bits(bits));

        String dataJson = mapper.writeValueAsString(statusListCreate);

        Date now = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600000))
                .subject("test-issuer")
                .audience("issuer-api")
                .claim("data", dataJson)
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }


    public void intercept(HttpTraceInterceptor interceptor) {

        var builder = RestClient.builder();
        builder = builder
                .requestInterceptor(interceptor);
        RestClient restClient = builder.build();
        var apiClient = new ApiClient(restClient).setBasePath(issuerConfig.getIssuerServiceUrl());
        credentialApi = new CredentialApiApi(apiClient);
        statusListApi = new StatusListApiApi(apiClient);
        actuatorApi = new ActuatorApi(apiClient);
    }
}