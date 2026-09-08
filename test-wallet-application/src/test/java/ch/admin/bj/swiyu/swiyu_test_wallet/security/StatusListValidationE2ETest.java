package ch.admin.bj.swiyu.swiyu_test_wallet.security;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.ConfigurationOverride;
import ch.admin.bj.swiyu.gen.issuer.model.CreateCredentialOfferRequest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialOfferMetadataDto;
import ch.admin.bj.swiyu.gen.issuer.model.StatusListCreate;
import ch.admin.bj.swiyu.gen.issuer.model.StatusListCreateConfig;
import ch.admin.bj.swiyu.gen.verifier.model.ConfigurationOverrideDto;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationErrorResponseCode;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementRouteSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JwtSupport;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockserver.matchers.TimeToLive;
import org.mockserver.matchers.Times;
import org.mockserver.model.ClearType;
import org.mockserver.model.HttpRequest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementRouteSupport.IDENTITY_TRUST_STATEMENT_PATH;
import static ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2.Tp2TrustStatementRouteSupport.identityTrustStatementPathRequest;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

/**
 * Exercises signed status-list substitution at the credential and TP2 consumer boundaries.
 * Each case changes one invariant and uses a fresh URI to avoid cached validation results.
 * The CACHED issuer variant enables signed metadata and TP2 statement injection.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-5.1">
 *     Token Status List JWT requirements</a>
 */
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.CACHED)
class StatusListValidationE2ETest extends BaseTest {

    private static final Duration LIFETIME = Duration.ofMinutes(5);
    private static final String ID_TS_TYPE = "swiyu-identity-trust-statement+jwt";
    // The same all-VALID two-bit list used by the existing registry mock (100,000 entries).
    private static final String VALID_STATUS_BITS =
            "eNrtwQEBAAAAgiD_r25IQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHwYYagAAQ";

    @ParameterizedTest(name = "credential status list: {0}")
    @EnumSource(value = StatusListCase.class, mode = EnumSource.Mode.EXCLUDE, names = "OTHER_SIGNER")
    @XrayTest(key = "EIDOMNI-1325", summary = "Verifier enforces status-list subject and JWT type",
            description = "A validly signed status list must match the credential URI and have typ=statuslist+jwt. "
                    + "Invalid sub or typ must produce a controlled error, FAILED state and one callback.")
    @Tag(ReportingTags.EDGE_CASE)
    void credentialStatusList_whenPresented_thenOnlyValidListAccepted(final StatusListCase testCase)
            throws Exception {
        // Given: a real credential with its own status list, collected before the registry substitution.
        final var statusList = issuerManager.getStatusListApi().createStatusList(new StatusListCreate()
                .maxLength(100000)
                .config(new StatusListCreateConfig().bits(2)));
        final var offer = issuerManager.createCredential(new CreateCredentialOfferRequest()
                .metadataCredentialSupportedId(List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT))
                .credentialSubjectData(CredentialSubjectFixtures.completeEmployeeProfile())
                .credentialMetadata(new CredentialOfferMetadataDto().deferred(false))
                .offerValiditySeconds(600)
                .statusLists(List.of(statusList.getStatusRegistryUrl())));
        final var batch = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final String credentialJwt = batch.getVerifiableCredential(0).split("~", 2)[0];
        final String uri = JwtSupport.decodePayloadToJsonNode(credentialJwt)
                .path("status").path("status_list").path("uri").asString();
        assertThat(uri)
                .isEqualTo(statusList.getStatusRegistryUrl().toString());

        final ECKey key = JWK.parseFromPEMEncodedObjects(issuerConfig.getIssuerAssertKeyPemString()).toECKey();
        final SignedJWT token = statusListToken(uri, issuerConfig.getIssuerDid(),
                issuerConfig.getIssuerAssertKeyId(), key, testCase);
        assertThat(token.verify(new ECDSAVerifier(key.toPublicJWK())))
                .as("Substitution keeps the credential issuer's signature valid")
                .isTrue();
        final HttpRequest statusRequest = statusRequest(uri);
        final var verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL()
                .createManagementResponse();
        final var requestObject = wallet.getVerificationRequestObject(verification.getVerificationDeeplink());
        final String presentation = batch.createPresentationForSdJwtIndex(0, requestObject);
        final int callbacksBefore = awaitStableVerifierCallbacks();
        final int fetchesBefore = mockServerClient.retrieveRecordedRequests(statusRequest).length;

        try {
            serveStatusList(statusRequest, token);

            // When / Then: only a fully valid list permits successful presentation verification.
            if (testCase == StatusListCase.VALID) {
                wallet.respondToVerification(requestObject, presentation);
                final var result = verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
                assertThat(result.getWalletResponse().getErrorCode())
                        .isNull();
                assertThat(result.getWalletResponse().getCredentialSubjectData())
                        .isNotEmpty();
            } else {
                final HttpClientErrorException error = assertThrows(HttpClientErrorException.class,
                        () -> wallet.respondToVerification(requestObject, presentation));
                ApiErrorAssert.assertThat(error)
                        .hasStatus(400)
                        .hasError("invalid_transaction_data")
                        .hasErrorCode(VerificationErrorResponseCode.UNRESOLVABLE_STATUS_LIST.getValue());
                final var result = verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
                assertThat(result.getWalletResponse().getErrorCode())
                        .isEqualTo(VerificationErrorResponseCode.UNRESOLVABLE_STATUS_LIST);
                assertThat(result.getWalletResponse().getErrorDescription())
                        .isNotBlank();
                assertThat(result.getWalletResponse().getCredentialSubjectData())
                        .isNullOrEmpty();
            }
            assertThat(mockServerClient.retrieveRecordedRequests(statusRequest).length)
                    .as("Verifier fetched the substituted status list")
                    .isGreaterThan(fetchesBefore);
            awaitOneVerifierCallback(callbacksBefore);
        } finally {
            mockServerClient.clear(statusRequest, ClearType.EXPECTATIONS);
        }
    }

    @ParameterizedTest(name = "verifier idTS status list: {0}")
    @EnumSource(StatusListCase.class)
    @XrayTest(key = "EIDOMNI-1326", summary = "Verifier rejects TP2 status-list substitution",
            description = "The request object includes idTS only when its status list has the expected sub, typ "
                    + "and signer DID. A different resolvable signer with a valid signature is rejected.")
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "TP2 request-object enrichment is required")
    void verifierIdentityTrustStatement_whenStatusListInvalid_thenOmitted(final StatusListCase testCase)
            throws Exception {
        // Given: a fresh subject and URI prevent either trust or status caches hiding the substitution.
        final String subject = swiyuDidVariant(verifierConfig.getVerifierDid());
        final String uri = freshStatusListUri();
        final ECKey trustKey = JWK.parseFromPEMEncodedObjects(trustConfig.getTrustAssertKeyPemString()).toECKey();
        final boolean otherSigner = testCase == StatusListCase.OTHER_SIGNER;
        final ECKey signingKey = otherSigner
                ? JWK.parseFromPEMEncodedObjects(issuerConfig.getIssuerAssertKeyPemString()).toECKey() : trustKey;
        final String kid = otherSigner ? issuerConfig.getIssuerAssertKeyId() : trustConfig.getTrustAssertKeyId();
        // Retain the expected iss even for the foreign kid: comparing iss alone must not authorize this signer.
        final SignedJWT token = statusListToken(uri, trustConfig.getTrustDid(), kid, signingKey, testCase);
        assertThat(token.verify(new ECDSAVerifier(signingKey.toPublicJWK())))
                .as("The status list is correctly signed by the key identified in kid")
                .isTrue();
        assertThat(token.getJWTClaimsSet().getIssuer())
                .isEqualTo(trustConfig.getTrustDid());
        if (otherSigner) {
            assertThat(token.verify(new ECDSAVerifier(trustKey.toPublicJWK())))
                    .as("A different issuer signed the status list")
                    .isFalse();
            assertThat(kid.substring(0, kid.indexOf('#')))
                    .isNotEqualTo(trustConfig.getTrustDid());
        }

        final HttpRequest identityRequest = identityRequest(subject);
        final HttpRequest statusRequest = statusRequest(uri);
        try {
            final String idTs = tp2Routes().registerIdentityTrustStatement(subject, LIFETIME, uri);
            assertThat(SignedJWT.parse(idTs).verify(new ECDSAVerifier(trustKey.toPublicJWK())))
                    .as("The referenced trust statement is validly signed by the trust issuer")
                    .isTrue();
            serveStatusList(statusRequest, token);
            final var verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL()
                    .configurationOverride(new ConfigurationOverrideDto().verifierDid(subject))
                    .jwtSecure()
                    .createManagementResponse();

            // When: fetching must succeed even when an unusable idTS has to be omitted.
            final String requestJwt = wallet.getVerificationDetailSigned(verification.getVerificationDeeplink());
            final var verifierInfo = JwtSupport.decodePayloadToJsonNode(requestJwt).path("verifier_info");
            final List<String> identities = verifierInfo.isArray()
                    ? verifierInfo.valueStream().map(node -> node.path("data").asString())
                    .filter(jwt -> ID_TS_TYPE.equals(JwtSupport.parse(jwt).getHeader().getType().toString()))
                    .toList() : List.of();

            // Then
            assertThat(identities)
                    .as("Only an idTS backed by a valid status list may be injected: %s", testCase)
                    .containsExactlyElementsOf(testCase == StatusListCase.VALID ? List.of(idTs) : List.of());
            assertThat(tp2Routes().identityTrustStatementRequests(subject))
                    .isPositive();
            assertThat(mockServerClient.retrieveRecordedRequests(statusRequest))
                    .as("Verifier evaluated this scenario's status list")
                    .isNotEmpty();
        } finally {
            mockServerClient.clear(identityRequest, ClearType.EXPECTATIONS);
            mockServerClient.clear(identityTrustStatementPathRequest(subject), ClearType.EXPECTATIONS);
            mockServerClient.clear(statusRequest, ClearType.EXPECTATIONS);
        }
    }

    @ParameterizedTest(name = "issuer idTS status-list typ: {0}")
    @EnumSource(value = StatusListCase.class, names = {"VALID", "JWT_TYPE", "SD_JWT_TYPE", "MISSING_TYPE"})
    @XrayTest(key = "EIDOMNI-1327", summary = "Issuer enforces TP2 status-list JWT type",
            description = "Issuer metadata includes the idTS only for typ=statuslist+jwt. Wrong or absent typ "
                    + "must omit the idTS without failing the metadata endpoint.")
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(issuer = {ImageTags.STABLE}, reason = "TP2 issuer metadata enrichment is required")
    void issuerIdentityTrustStatement_whenStatusListTypeInvalid_thenOmitted(final StatusListCase testCase)
            throws Exception {
        // Given
        final String subject = swiyuDidVariant(issuerConfig.getIssuerDid());
        final String uri = freshStatusListUri();
        final ECKey key = JWK.parseFromPEMEncodedObjects(trustConfig.getTrustAssertKeyPemString()).toECKey();
        final SignedJWT token = statusListToken(uri, trustConfig.getTrustDid(),
                trustConfig.getTrustAssertKeyId(), key, testCase);
        assertThat(token.verify(new ECDSAVerifier(key.toPublicJWK())))
                .as("The wrong or absent typ does not invalidate the cryptographic signature")
                .isTrue();
        final HttpRequest identityRequest = identityRequest(subject);
        final HttpRequest statusRequest = statusRequest(uri);
        try {
            final String idTs = tp2Routes().registerIdentityTrustStatement(subject, LIFETIME, uri);
            serveStatusList(statusRequest, token);
            final var statusList = issuerManager.getStatusListApi().createStatusList(new StatusListCreate()
                    .maxLength(100000)
                    .config(new StatusListCreateConfig().bits(2))
                    .configurationOverride(new ConfigurationOverride().issuerDid(subject)
                            .verificationMethod(issuerConfig.getIssuerAuthKeyId())));
            final var offer = issuerManager.createCredential(new CreateCredentialOfferRequest()
                    .metadataCredentialSupportedId(List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT))
                    .credentialSubjectData(CredentialSubjectFixtures.completeEmployeeProfile())
                    .credentialMetadata(new CredentialOfferMetadataDto().deferred(false))
                    .offerValiditySeconds(600)
                    .statusLists(List.of(statusList.getStatusRegistryUrl()))
                    .configurationOverride(new ConfigurationOverride().issuerDid(subject)
                            .verificationMethod(subject + "#assert-key-01")));
            final var entry = wallet.createWalletBatchEntry();
            entry.receiveDeepLinkAndValidateIt(toUri(offer.getOfferDeeplink()));

            // When
            final var metadata = wallet.getIssuerWellKnownMetadata(entry);

            // Then
            if (testCase == StatusListCase.VALID) {
                assertThat(metadata.getCredentialIssuerIdentityTrustStatement())
                        .isEqualTo(idTs);
            } else {
                assertThat(metadata.getCredentialIssuerIdentityTrustStatement())
                        .as("Issuer must omit idTS when the status-list typ is %s", testCase)
                        .isNullOrEmpty();
            }
            assertThat(tp2Routes().identityTrustStatementRequests(subject))
                    .isPositive();
            assertThat(mockServerClient.retrieveRecordedRequests(statusRequest))
                    .as("Issuer evaluated this scenario's status list")
                    .isNotEmpty();
        } finally {
            mockServerClient.clear(identityRequest, ClearType.EXPECTATIONS);
            mockServerClient.clear(identityTrustStatementPathRequest(subject), ClearType.EXPECTATIONS);
            mockServerClient.clear(statusRequest, ClearType.EXPECTATIONS);
        }
    }

    private SignedJWT statusListToken(String uri, String issuer, String kid, ECKey key, StatusListCase testCase)
            throws Exception {
        final String subject = switch (testCase) {
            case MISMATCHED_SUB -> freshStatusListUri();
            case MISSING_SUB -> null;
            default -> uri;
        };
        final JOSEObjectType type = switch (testCase) {
            case JWT_TYPE -> JOSEObjectType.JWT;
            case SD_JWT_TYPE -> new JOSEObjectType("vc+sd-jwt");
            case MISSING_TYPE -> null;
            default -> new JOSEObjectType("statuslist+jwt");
        };
        final Instant now = Instant.now();
        final SignedJWT token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(kid).type(type).build(), new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .issueTime(Date.from(now.minusSeconds(30)))
                .expirationTime(Date.from(now.plus(LIFETIME)))
                .claim("status_list", Map.of("bits", 2, "lst", VALID_STATUS_BITS))
                .build());
        token.sign(new ECDSASigner(key));
        return token;
    }

    private void serveStatusList(HttpRequest statusRequest, SignedJWT token) {
        mockServerClient.when(statusRequest, Times.unlimited(), TimeToLive.unlimited(), 200)
                .respond(response().withStatusCode(200)
                        .withHeader("Content-Type", "application/statuslist+jwt")
                        .withBody(token.serialize()));
    }

    private String freshStatusListUri() {
        return "https://mockserver:1080/api/v1/statuslist/security-" + UUID.randomUUID() + ".jwt";
    }

    private HttpRequest statusRequest(String uri) {
        return request().withMethod("GET").withPath(Pattern.quote(URI.create(uri).getPath()));
    }

    private HttpRequest identityRequest(String subject) {
        return request().withMethod("GET").withPath(IDENTITY_TRUST_STATEMENT_PATH + "/?")
                .withQueryStringParameter("sub", subject);
    }

    private Tp2TrustStatementRouteSupport tp2Routes() {
        return new Tp2TrustStatementRouteSupport(mockServerClient, issuerConfig, verifierConfig,
                trustConfig, new ObjectMapper());
    }

    private enum StatusListCase {
        VALID, MISMATCHED_SUB, MISSING_SUB, OTHER_SIGNER, JWT_TYPE, SD_JWT_TYPE, MISSING_TYPE
    }
}
