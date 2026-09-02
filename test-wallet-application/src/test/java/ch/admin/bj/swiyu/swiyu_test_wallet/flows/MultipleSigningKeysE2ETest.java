package ch.admin.bj.swiyu.swiyu_test_wallet.flows;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.ConfigurationOverride;
import ch.admin.bj.swiyu.gen.issuer.model.CreateCredentialOfferRequest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialOfferMetadataDto;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.gen.verifier.model.ConfigurationOverrideDto;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseVerifiers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.DEFAULT_CREDENTIAL_ID;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.MULTI_SIGNING_KEYS)
@UseVerifiers(VerifierVariant.MULTI_SIGNING_KEYS)
@DisableIfImageTag(
        issuer = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
        verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
        reason = "Multiple signing identities are not available on these component images"
)
class MultipleSigningKeysE2ETest extends BaseTest {

    private static final String CLIENT_ID_PREFIX = "decentralized_identifier:";

    @Test
    @XrayTest(
            key = "EIDOMNI-1236",
            summary = "Issuer selects the signing key bound to each configured DID",
            description = """
                    Given one issuer runtime configured with a default and a migration signing identity.
                    When the wallet collects one credential for each identity through OID4VCI.
                    Then each SD-JWT contains the matching issuer and kid and verifies only with its bound key.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.HAPPY_PATH)
    void issuerWithTwoSigningIdentities_whenCredentialsIssued_thenEachUsesItsBoundDidAndKey() throws Exception {
        // Given
        assertThat(issuerConfig.getAdditionalSigningIdentities())
                .as("The multi-signing issuer variant must contain one migration identity")
                .hasSize(1);
        final IssuerConfig migrationIdentity = issuerConfig.getAdditionalSigningIdentities().getFirst();
        assertThat(migrationIdentity.getIssuerDid())
                .isNotEqualTo(issuerConfig.getIssuerDid());
        assertThat(migrationIdentity.getIssuerAssertKeyId())
                .isNotEqualTo(issuerConfig.getIssuerAssertKeyId());

        final Map<String, Object> defaultClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final CredentialWithDeeplinkResponse defaultOffer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                defaultClaims
        );

        final ConfigurationOverride statusListOverride = new ConfigurationOverride()
                .issuerDid(migrationIdentity.getIssuerDid())
                .verificationMethod(migrationIdentity.getIssuerAuthKeyId());
        final StatusList migrationStatusList = issuerManager.createStatusList(100000, 2, statusListOverride);
        mockServerClientConfig.setCurrentStatusList(
                migrationIdentity.getIssuerDid(),
                migrationStatusList.getStatusRegistryUrl()
        );

        final Map<String, Object> migrationClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final CreateCredentialOfferRequest migrationRequest = new CreateCredentialOfferRequest()
                .metadataCredentialSupportedId(List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT))
                .credentialSubjectData(migrationClaims)
                .credentialMetadata(new CredentialOfferMetadataDto().deferred(false))
                .offerValiditySeconds(86400)
                .statusLists(List.of(migrationStatusList.getStatusRegistryUrl()))
                .configurationOverride(new ConfigurationOverride()
                        .issuerDid(migrationIdentity.getIssuerDid())
                        .verificationMethod(migrationIdentity.getIssuerAssertKeyId()));
        final CredentialWithDeeplinkResponse migrationOffer = issuerManager.createCredential(migrationRequest);

        // When
        final WalletBatchEntry defaultWalletEntry = wallet.collectOffer(toUri(defaultOffer.getOfferDeeplink()));
        final WalletBatchEntry migrationWalletEntry = wallet.collectOffer(toUri(migrationOffer.getOfferDeeplink()));
        final SignedJWT defaultCredential = SignedJWT.parse(
                defaultWalletEntry.getVerifiableCredential(0).split("~", -1)[0]
        );
        final SignedJWT migrationCredential = SignedJWT.parse(
                migrationWalletEntry.getVerifiableCredential(0).split("~", -1)[0]
        );
        final ECDSAVerifier defaultKeyVerifier = new ECDSAVerifier(
                KeyUtil.createJWKFromKeyPair(issuerConfig.getKeyPair()).toECKey()
        );
        final ECDSAVerifier migrationKeyVerifier = new ECDSAVerifier(
                KeyUtil.createJWKFromKeyPair(migrationIdentity.getKeyPair()).toECKey()
        );

        // Then
        issuerManager.verifyStatus(defaultOffer.getManagementId(), CredentialStatusType.ISSUED);
        issuerManager.verifyStatus(migrationOffer.getManagementId(), CredentialStatusType.ISSUED);
        assertThat(defaultCredential.getJWTClaimsSet().getIssuer())
                .isEqualTo(issuerConfig.getIssuerDid());
        assertThat(defaultCredential.getHeader().getKeyID())
                .isEqualTo(issuerConfig.getIssuerAssertKeyId());
        assertThat(defaultCredential.verify(defaultKeyVerifier))
                .isTrue();
        assertThat(defaultCredential.verify(migrationKeyVerifier))
                .as("The default credential must not be signed by the migration key")
                .isFalse();
        assertThat(migrationCredential.getJWTClaimsSet().getIssuer())
                .isEqualTo(migrationIdentity.getIssuerDid());
        assertThat(migrationCredential.getHeader().getKeyID())
                .isEqualTo(migrationIdentity.getIssuerAssertKeyId());
        assertThat(migrationCredential.verify(migrationKeyVerifier))
                .isTrue();
        assertThat(migrationCredential.verify(defaultKeyVerifier))
                .as("The migration credential must not fall back to the default key")
                .isFalse();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1236",
            summary = "Verifier selects the signing key bound to each configured DID",
            description = """
                    Given one verifier runtime configured with a default and a migration signing identity.
                    When the wallet fetches and completes one OID4VP request for each identity.
                    Then each request object contains the matching issuer, client_id and kid, verifies only with its
                    bound key, and both verification transactions reach SUCCESS.
                    """
    )
    @Tag(ReportingTags.UCV_O1A)
    @Tag(ReportingTags.HAPPY_PATH)
    void verifierWithTwoSigningIdentities_whenRequestsCompleted_thenEachUsesItsBoundDidAndKey() throws Exception {
        // Given
        assertThat(verifierConfig.getAdditionalSigningIdentities())
                .as("The multi-signing verifier variant must contain one migration identity")
                .hasSize(1);
        final VerifierConfig migrationIdentity = verifierConfig.getAdditionalSigningIdentities().getFirst();
        assertThat(migrationIdentity.getVerifierDid())
                .isNotEqualTo(verifierConfig.getVerifierDid());
        assertThat(migrationIdentity.getVerifierAuthKeyId())
                .isNotEqualTo(verifierConfig.getVerifierAuthKeyId());

        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT,
                CredentialSubjectFixtures.completeEmployeeProfile()
        );
        final WalletBatchEntry walletEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
        final ManagementResponse defaultVerification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL()
                .jwtSecure()
                .createManagementResponse();
        final ManagementResponse migrationVerification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL()
                .jwtSecure()
                .configurationOverride(new ConfigurationOverrideDto()
                        .verifierDid(migrationIdentity.getVerifierDid())
                        .verificationMethod(migrationIdentity.getVerifierAuthKeyId()))
                .createManagementResponse();

        // When
        final SignedJWT defaultRequestJwt = SignedJWT.parse(
                wallet.getVerificationDetailSigned(defaultVerification.getVerificationDeeplink())
        );
        final SignedJWT migrationRequestJwt = SignedJWT.parse(
                wallet.getVerificationDetailSigned(migrationVerification.getVerificationDeeplink())
        );
        final RequestObject defaultRequest = wallet.getVerificationRequestObject(
                defaultVerification.getVerificationDeeplink()
        );
        final RequestObject migrationRequest = wallet.getVerificationRequestObject(
                migrationVerification.getVerificationDeeplink()
        );
        final ResponseEntity<String> defaultWalletResponse = wallet.respondToVerificationWithVpTokens(
                defaultRequest,
                List.of(walletEntry.createSelectiveDisclosurePresentationForSdJwtIndex(0, defaultRequest))
        );
        final ResponseEntity<String> migrationWalletResponse = wallet.respondToVerificationWithVpTokens(
                migrationRequest,
                List.of(walletEntry.createSelectiveDisclosurePresentationForSdJwtIndex(0, migrationRequest))
        );
        final ManagementResponse defaultResult = verifierManager.verifyState(
                defaultVerification.getId(),
                VerificationStatus.SUCCESS
        );
        final ManagementResponse migrationResult = verifierManager.verifyState(
                migrationVerification.getId(),
                VerificationStatus.SUCCESS
        );
        final ECDSAVerifier defaultKeyVerifier = new ECDSAVerifier(
                JWK.parseFromPEMEncodedObjects(verifierConfig.getVerifierAuthKeyPemString()).toECKey()
        );
        final ECDSAVerifier migrationKeyVerifier = new ECDSAVerifier(
                JWK.parseFromPEMEncodedObjects(migrationIdentity.getVerifierAuthKeyPemString()).toECKey()
        );
        final boolean migrationSignatureMatchesMigrationKey = migrationRequestJwt.verify(migrationKeyVerifier);
        final boolean migrationSignatureMatchesDefaultKey = migrationRequestJwt.verify(defaultKeyVerifier);

        // Then
        assertThat(defaultWalletResponse.getStatusCode().is2xxSuccessful())
                .isTrue();
        assertThat(migrationWalletResponse.getStatusCode().is2xxSuccessful())
                .isTrue();
        assertThat(defaultRequestJwt.getJWTClaimsSet().getIssuer())
                .isEqualTo(CLIENT_ID_PREFIX + verifierConfig.getVerifierDid());
        assertThat(defaultRequestJwt.getJWTClaimsSet().getStringClaim("client_id"))
                .isEqualTo(CLIENT_ID_PREFIX + verifierConfig.getVerifierDid());
        assertThat(defaultRequestJwt.getHeader().getKeyID())
                .isEqualTo(verifierConfig.getVerifierAuthKeyId());
        assertThat(defaultRequestJwt.verify(defaultKeyVerifier))
                .isTrue();
        assertThat(defaultRequestJwt.verify(migrationKeyVerifier))
                .as("The default request object must not be signed by the migration key")
                .isFalse();
        assertThat(migrationRequestJwt.getJWTClaimsSet().getIssuer())
                .isEqualTo(CLIENT_ID_PREFIX + migrationIdentity.getVerifierDid());
        assertThat(migrationRequestJwt.getJWTClaimsSet().getStringClaim("client_id"))
                .isEqualTo(CLIENT_ID_PREFIX + migrationIdentity.getVerifierDid());
        assertThat(migrationRequestJwt.getHeader().getKeyID())
                .isEqualTo(migrationIdentity.getVerifierAuthKeyId());
        assertThat(List.of(migrationSignatureMatchesMigrationKey, migrationSignatureMatchesDefaultKey))
                .as("The migration request object must match only [migration key, default key]")
                .containsExactly(true, false);
        assertThat(defaultResult.getWalletResponse().getCredentialSubjectData())
                .containsOnlyKeys(DEFAULT_CREDENTIAL_ID);
        assertThat(migrationResult.getWalletResponse().getCredentialSubjectData())
                .containsOnlyKeys(DEFAULT_CREDENTIAL_ID);
    }
}
