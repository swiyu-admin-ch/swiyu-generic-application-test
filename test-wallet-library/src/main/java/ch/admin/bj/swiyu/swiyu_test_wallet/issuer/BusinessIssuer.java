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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import static io.netty.handler.codec.http.HttpHeaders.Values.APPLICATION_JSON;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@Getter
@Slf4j
public class BusinessIssuer {

    private CredentialApiApi credentialApi;
    private StatusListApiApi statusListApi;
    private ActuatorApi actuatorApi;

    private StatusList statusList;
    private IssuerConfig issuerConfig;

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
        statusListCreate.setMaxLength(size);
        statusListCreate.setConfig(new StatusListCreateConfig().bits(bits));

        statusList = statusListApi.createStatusList(statusListCreate);

        return statusList;
    }

    public StatusList createStatusList(int size, int bits, String jwt) {
        applyJwt(jwt);

        ch.admin.bj.swiyu.gen.issuer.model.StatusListCreate statusListCreate = new ch.admin.bj.swiyu.gen.issuer.model.StatusListCreate();
        statusListCreate.setMaxLength(size);
        statusListCreate.setConfig(new StatusListCreateConfig().bits(bits));

        statusList = statusListApi.createStatusList(statusListCreate);

        return statusList;
    }

    public CredentialWithDeeplinkResponse createCredentialOffer(String supportedMetadataId) {
        return createCredentialOffer(supportedMetadataId, CredentialOffer.defaultSubjectData(), false);
    }

    public CredentialWithDeeplinkResponse createCredentialOffer(String supportedMetadataId, Map<String, Object> subjectClaims) {
        return createCredentialOffer(supportedMetadataId, subjectClaims, false);
    }

    public CredentialWithDeeplinkResponse createCredentialOffer(String supportedMetadataId, Map<String, Object> subjectClaims, final boolean deferred) {
        CredentialOfferMetadataDto credentialOfferMetadataDto = new CredentialOfferMetadataDto();
        credentialOfferMetadataDto.setDeferred(deferred);

        var offer = createCredentialOfferRequest(supportedMetadataId, credentialOfferMetadataDto, subjectClaims);

        return createCredential(offer);
    }

    public CredentialWithDeeplinkResponse createDeferredCredentialOffer(String supportedMetadataId) {
        return createCredentialOffer(supportedMetadataId, CredentialOffer.defaultSubjectData(), true);
    }

    public CredentialWithDeeplinkResponse createDeferredCredentialOffer(String supportedMetadataId, Map<String, Object> subjectClaims) {
        return createCredentialOffer(supportedMetadataId, subjectClaims, true);
    }

    public CredentialWithDeeplinkResponse createCredential(CreateCredentialOfferRequest offer) {
        return credentialApi.createCredential1(offer);
    }

    public void updateState(UUID id,
                            ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType newState) {
        updateVcStatus(id, newState);
    }

    public CredentialManagementDto getCredentialById(UUID id) {
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

    private CreateCredentialOfferRequest createCredentialOfferRequest(String supportedMetadataId, CredentialOfferMetadataDto credentialMetadata, Map<String, Object> subjectClaims) {
        final CreateCredentialOfferRequest offer = new CreateCredentialOfferRequest();
        offer.setCredentialSubjectData(subjectClaims);
        offer.setStatusLists(List.of(statusList.getStatusRegistryUrl()));
        offer.setCredentialMetadata(credentialMetadata);
        offer.setMetadataCredentialSupportedId(List.of(supportedMetadataId));
        offer.setOfferValiditySeconds(86400); // 24h
        return offer;
    }

    public StatusList createStatusListWithSignedJwt(final PrivateKey privateKey, final String keyId, int size, int bits) {
        String jwt;
        try {
            jwt = createSignedJwtForStatusList(privateKey, keyId, size, bits);
        } catch (JsonProcessingException | JOSEException e) {
            throw new IllegalStateException(e);
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

    public CredentialWithDeeplinkResponse createDeferredCredentialWithSignedJwt(final PrivateKey privateKey, final String keyId, final String supportedMetadataId) {
        return createCredentialWithSignedJwt(privateKey, keyId, supportedMetadataId, true);
    }

    public CredentialWithDeeplinkResponse createCredentialWithSignedJwt(final PrivateKey privateKey, final String keyId, final String supportedMetadataId) {
        return createCredentialWithSignedJwt(privateKey, keyId, supportedMetadataId, false);
    }

    public CredentialWithDeeplinkResponse createCredentialWithSignedJwt(final PrivateKey privateKey, final String keyId, final String supportedMetadataId, final boolean deferred) {
        String jwt;
        try {
            jwt = createSignedJwtForCredential(privateKey, keyId, supportedMetadataId, deferred);
        } catch (JsonProcessingException | JOSEException e) {
            throw new IllegalStateException(e);
        }

        final RestClient restClient = RestClient.builder().build();
        final String url = issuerConfig.getIssuerServiceUrl() + "/management/api/credentials";
        return restClient.post()
                .uri(url)
                .header(HttpHeaders.CONTENT_TYPE, APPLICATION_JSON)
                .body(jwt)
                .retrieve()
                .body(CredentialWithDeeplinkResponse.class);
    }

    public void updateStateWithSignedJwt(final PrivateKey privateKey, final String keyId, final UUID id,
                                         final UpdateCredentialStatusRequestType newState) {
        String jwt;
        try {
            jwt = createSignedJwtForUpdateState(privateKey, keyId, newState);
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot sign JWT", e);
        }

        final RestClient restClient = RestClient.builder().build();
        final String url = issuerConfig.getIssuerServiceUrl() + "/management/api/credentials/" + id +
                          "/status?credentialStatus=" + newState;
        restClient.patch()
                .uri(url)
                .header(HttpHeaders.CONTENT_TYPE, APPLICATION_JSON)
                .body(jwt)
                .retrieve()
                .toBodilessEntity();
    }

    private String createSignedJwtWithEcKey(final PrivateKey privateKey, final String keyId, final String data)
            throws JOSEException {
        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(keyId)
                .build();

        final Date now = new Date();
        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600000))
                .subject("test-issuer")
                .audience("issuer-api")
                .claim("data", data)
                .build();

        final SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        final JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    private String createSignedJwtForStatusList(final PrivateKey privateKey, final String keyId, final int size,
                                                final int bits) throws JsonProcessingException, JOSEException {
        final ObjectMapper mapper = new ObjectMapper();

        final StatusListCreate statusListCreate = new StatusListCreate();
        statusListCreate.setMaxLength(size);
        statusListCreate.setConfig(new StatusListCreateConfig().bits(bits));

        final String data = mapper.writeValueAsString(statusListCreate);

        return createSignedJwtWithEcKey(privateKey, keyId, data);
    }

    private String createSignedJwtForCredential(final PrivateKey privateKey, final String keyId,
                                                String supportedMetadataId) throws JsonProcessingException,
            JOSEException {
        return createSignedJwtForCredential(privateKey, keyId, supportedMetadataId, false);
    }

    private String createSignedJwtForCredential(final PrivateKey privateKey, final String keyId,
                                                String supportedMetadataId, boolean deferred) throws JsonProcessingException,
            JOSEException {
        final ObjectMapper mapper = new ObjectMapper();

        final CredentialOfferMetadataDto credentialOfferMetadataDto = new CredentialOfferMetadataDto();
        credentialOfferMetadataDto.setDeferred(deferred);

        final CreateCredentialOfferRequest offer = createCredentialOfferRequest(supportedMetadataId, credentialOfferMetadataDto, CredentialOffer.defaultSubjectData());

        final String data = mapper.writeValueAsString(offer);

        return createSignedJwtWithEcKey(privateKey, keyId, data);
    }

    private String createSignedJwtForUpdateState(final PrivateKey privateKey, final String keyId,
                                                 final UpdateCredentialStatusRequestType newState) throws JOSEException {
        final ObjectMapper mapper = new ObjectMapper();

        try {
            final String data = mapper.writeValueAsString(newState);
            return createSignedJwtWithEcKey(privateKey, keyId, data);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Cannot sign JWT for updating state", e);
        }
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