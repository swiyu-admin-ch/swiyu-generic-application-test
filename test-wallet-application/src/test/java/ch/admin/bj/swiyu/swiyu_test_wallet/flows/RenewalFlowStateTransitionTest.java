package ch.admin.bj.swiyu.swiyu_test_wallet.flows;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.OAuthToken;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.support.TestConstants;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.DPoPSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.HttpClientErrorException;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@ActiveProfiles({"issuer-strict"})
public class RenewalFlowStateTransitionTest extends BaseTest {

    private KeyPair dpopKeyPair;
    private ECKey dpopPublicKey;

    @BeforeAll
    void setUp() {
        dpopKeyPair = ECCryptoSupport.generateECKeyPair();
        dpopPublicKey = new ECKey.Builder(
                Curve.P_256,
                (java.security.interfaces.ECPublicKey) dpopKeyPair.getPublic())
                .keyUse(KeyUse.SIGNATURE)
                .keyID("holder-dpop-key-" + UUID.randomUUID())
                .build();
    }

    private CredentialWithDeeplinkResponse initializeCredentials(final WalletBatchEntry entry) {
        final CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialWithSignedJwt(jwtKey, "test-key-1", CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);

        entry.receiveDeepLinkAndValidateIt(toUri(offer.getOfferDeeplink()));
        entry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(entry));
        entry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(entry));
        entry.setCredentialConfigurationSupported();

        final String nonceInitial = wallet.getDpopNonce(entry);

        final String dpopInitial = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(), nonceInitial, dpopKeyPair, dpopPublicKey);

        final OAuthToken token1 = wallet.collectTokenWithDPoP(entry, dpopInitial);
        entry.setToken(token1);

        entry.generateHolderKeys();
        entry.createProofs();

        final String nonceRenewalCredential = wallet.getDpopNonce(entry);

        final String dpopRenewalCredential = DPoPSupport.createDpopProofForToken(
                entry.getIssuerCredentialUri().toString(), nonceRenewalCredential, dpopKeyPair, dpopPublicKey, entry.getToken().getAccessToken());

        final var credentialResponseRenewal = wallet.postCredentialRequestWithRefreshToken(entry, entry.getToken().getAccessToken(), dpopRenewalCredential);
        assertThat(credentialResponseRenewal).isNotNull();
        final List<String> batch1 = entry.getIssuedCredentials();

        for (int i = 0; i < batch1.size(); i++) {
            final String deepLink = verifierManager.verificationRequest()
                    .acceptedIssuerDid(entry.getIssuerDid(i))
                    .withUniversityDCQL()
                    .create();

            final RequestObject details = wallet.getVerificationDetailsUnsigned(deepLink);
            final String presentation = entry.createPresentationForSdJwtIndex(i, details);

            wallet.respondToVerificationV1(details, presentation);
            verifierManager.verifyState();
        }

        return offer;
    }

    @Test
    @XrayTest(
            key = "@TODO",
            summary = "All credentials (initial and renewed) are revoked and cannot be verified",
            description = """
                    This test validates the complete renewal and revocation flow where credentials are initially
                    issued, renewed through refresh token mechanism, and then all credentials (both initial batch
                    and renewed batch) are revoked by the credential management. The test ensures that revocation
                    is applied consistently to all credential batches and that verification fails for all revoked
                    credentials regardless of whether they are from the initial or renewed batch.
                    """)
    @Tag("@TODO")
    @Tag("happy_path")
    @DisableIfImageTag(
            issuer = {"stable", "staging", "rc", "dev"},
            reason = "This feature is not available yet"
    )
    void renewalFlow_whenAllCredentialsRevoked_thenBothInitialAndRenewedRejected() {
        final List<String> allCredentials = new ArrayList<>();
        final WalletBatchEntry initialEntry = new WalletBatchEntry(wallet);
        final WalletBatchEntry renewedEntry = new WalletBatchEntry(wallet);

        log.info("Create initial credentials");
        final CredentialWithDeeplinkResponse offer = initializeCredentials(initialEntry);
        allCredentials.addAll(initialEntry.getIssuedCredentials());

        renewedEntry.setIssuerVCDeepLink(initialEntry.getIssuerVCDeepLink());
        renewedEntry.setCredentialOffer(initialEntry.getCredentialOffer());
        renewedEntry.setIssuerWellKnownConfiguration(initialEntry.getIssuerWellKnownConfiguration());
        renewedEntry.setIssuerMetadata(initialEntry.getIssuerMetadata());
        renewedEntry.setCredentialConfigurationSupported();
        renewedEntry.setToken(initialEntry.getToken());

        log.info("Retrieve a refresh token");
        String nonce = wallet.getCNonce(renewedEntry);
        String dpop = DPoPSupport.createDpopProofForToken(
                renewedEntry.getIssuerTokenUri().toString(), nonce, dpopKeyPair, dpopPublicKey,
                renewedEntry.getToken().getRefreshToken());
        final OAuthToken token = wallet.collectRefreshTokenWithDPoP(renewedEntry, dpop);
        renewedEntry.setToken(token);

        log.info("Generate proofs with a fresh nonce");
        nonce = wallet.getCNonce(renewedEntry);
        renewedEntry.generateHolderKeys();
        renewedEntry.createProofs(nonce);

        log.info("Renew credentials using the refresh token");
        nonce = wallet.getDpopNonce(renewedEntry);
        dpop = DPoPSupport.createDpopProofForToken(
                renewedEntry.getIssuerCredentialUri().toString(), nonce, dpopKeyPair, dpopPublicKey,
                token.getAccessToken());

        final var credentialResponse = wallet.postCredentialRequestWithRefreshToken(renewedEntry, token.getAccessToken(), dpop);
        assertThat(credentialResponse).isNotNull();
        allCredentials.addAll(renewedEntry.getIssuedCredentials());

        assertThat(allCredentials)
                .as("All credentials have been issued")
                .isNotNull()
                .hasSize(TestConstants.UNIVERSITY_EXAMPLE_BATCH_SIZE * 2);

        assertThat(allCredentials)
                .as("All credential JWTs must be unique")
                .doesNotHaveDuplicates();

        issuerManager.updateStateWithSignedJwt(
                jwtKey, "test-key-1",
                offer.getManagementId(),
                UpdateCredentialStatusRequestType.REVOKED
        );

        for (int i = 0; i < initialEntry.getIssuedCredentials().size(); i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(true)
                    .createManagementResponse();

            final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(toUri(verification.getVerificationDeeplink()));
            final String presentation = initialEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            log.info("Presenting credential from initial batch, which should be revoked " + presentation);
            final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
                wallet.respondToVerification(SwiyuApiVersionConfig.V1, verificationDetails, presentation);
            });
            ApiErrorAssert.assertThat(ex)
                    .hasError("invalid_transaction_data")
                    .hasErrorDescription("Credential has been Revoked!");
            verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
        }

        for (int i = 0; i < renewedEntry.getIssuedCredentials().size(); i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(true)
                    .createManagementResponse();

            final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(toUri(verification.getVerificationDeeplink()));
            final String presentation = renewedEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            log.info("Presenting credential from initial batch, which should be revoked " + presentation);
            final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
                wallet.respondToVerification(SwiyuApiVersionConfig.V1, verificationDetails, presentation);
            });
            ApiErrorAssert.assertThat(ex)
                    .hasError("invalid_transaction_data")
                    .hasErrorDescription("Credential has been Revoked!");
            verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
        }
    }

    @Test
    @XrayTest(
            key = "@TODO",
            summary = "All credentials (initial and renewed) are revoked and cannot be verified",
            description = """
                    This test validates the complete renewal and revocation flow where credentials are initially
                    issued, renewed through refresh token mechanism, and then all credentials (both initial batch
                    and renewed batch) are revoked by the credential management. The test ensures that revocation
                    is applied consistently to all credential batches and that verification fails for all revoked
                    credentials regardless of whether they are from the initial or renewed batch.
                    """)
    @Tag("@TODO")
    @Tag("happy_path")
    @DisableIfImageTag(
            issuer = {"stable", "staging", "rc", "dev"},
            reason = "This feature is not available yet"
    )
    void renewalFlow_whenAllCredentialsSuspended_thenBothInitialAndRenewedRejected() {
        final List<String> allCredentials = new ArrayList<>();
        final WalletBatchEntry initialEntry = new WalletBatchEntry(wallet);
        final WalletBatchEntry renewedEntry = new WalletBatchEntry(wallet);

        log.info("Create initial credentials");
        final CredentialWithDeeplinkResponse offer = initializeCredentials(initialEntry);
        allCredentials.addAll(initialEntry.getIssuedCredentials());

        renewedEntry.setIssuerVCDeepLink(initialEntry.getIssuerVCDeepLink());
        renewedEntry.setCredentialOffer(initialEntry.getCredentialOffer());
        renewedEntry.setIssuerWellKnownConfiguration(initialEntry.getIssuerWellKnownConfiguration());
        renewedEntry.setIssuerMetadata(initialEntry.getIssuerMetadata());
        renewedEntry.setCredentialConfigurationSupported();
        renewedEntry.setToken(initialEntry.getToken());

        log.info("Retrieve a refresh token");
        String nonce = wallet.getCNonce(renewedEntry);
        String dpop = DPoPSupport.createDpopProofForToken(
                renewedEntry.getIssuerTokenUri().toString(), nonce, dpopKeyPair, dpopPublicKey,
                renewedEntry.getToken().getRefreshToken());
        final OAuthToken token = wallet.collectRefreshTokenWithDPoP(renewedEntry, dpop);
        renewedEntry.setToken(token);

        log.info("Generate proofs with a fresh nonce");
        nonce = wallet.getCNonce(renewedEntry);
        renewedEntry.generateHolderKeys();
        renewedEntry.createProofs(nonce);

        log.info("Renew credentials using the refresh token");
        nonce = wallet.getDpopNonce(renewedEntry);
        dpop = DPoPSupport.createDpopProofForToken(
                renewedEntry.getIssuerCredentialUri().toString(), nonce, dpopKeyPair, dpopPublicKey,
                token.getAccessToken());

        final var credentialResponse = wallet.postCredentialRequestWithRefreshToken(renewedEntry, token.getAccessToken(), dpop);
        assertThat(credentialResponse).isNotNull();
        allCredentials.addAll(renewedEntry.getIssuedCredentials());

        assertThat(allCredentials)
                .as("All credentials have been issued")
                .isNotNull()
                .hasSize(TestConstants.UNIVERSITY_EXAMPLE_BATCH_SIZE * 2);

        assertThat(allCredentials)
                .as("All credential JWTs must be unique")
                .doesNotHaveDuplicates();

        issuerManager.updateStateWithSignedJwt(
                jwtKey, "test-key-1",
                offer.getManagementId(),
                UpdateCredentialStatusRequestType.SUSPENDED
        );

        for (int i = 0; i < initialEntry.getIssuedCredentials().size(); i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(true)
                    .createManagementResponse();

            final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(toUri(verification.getVerificationDeeplink()));
            final String presentation = initialEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            log.info("Presenting credential from initial batch, which should be revoked " + presentation);
            final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
                wallet.respondToVerification(SwiyuApiVersionConfig.V1, verificationDetails, presentation);
            });
            ApiErrorAssert.assertThat(ex)
                    .hasError("invalid_transaction_data")
                    .hasErrorDescription("Credential has been Suspended!");
            verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
        }

        for (int i = 0; i < renewedEntry.getIssuedCredentials().size(); i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(true)
                    .createManagementResponse();

            final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(toUri(verification.getVerificationDeeplink()));
            final String presentation = renewedEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            log.info("Presenting credential from initial batch, which should be revoked " + presentation);
            final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
                wallet.respondToVerification(SwiyuApiVersionConfig.V1, verificationDetails, presentation);
            });
            ApiErrorAssert.assertThat(ex)
                    .hasError("invalid_transaction_data")
                    .hasErrorDescription("Credential has been Suspended!");
            verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
        }
    }

    @Test
    @XrayTest(
            key = "@TODO",
            summary = "All credentials (initial and renewed) are revoked and cannot be verified",
            description = """
                    This test validates the complete renewal and revocation flow where credentials are initially
                    issued, renewed through refresh token mechanism, and then all credentials (both initial batch
                    and renewed batch) are revoked by the credential management. The test ensures that revocation
                    is applied consistently to all credential batches and that verification fails for all revoked
                    credentials regardless of whether they are from the initial or renewed batch.
                    """)
    @Tag("@TODO")
    @Tag("happy_path")
    @DisableIfImageTag(
            issuer = {"stable", "staging", "rc", "dev"},
            reason = "This feature is not available yet"
    )
    void renewalFlow_whenRevokedBeforeRenew_thenBothInitialAndRenewedRejected() {
        final List<String> allCredentials = new ArrayList<>();
        final WalletBatchEntry initialEntry = new WalletBatchEntry(wallet);
        final WalletBatchEntry renewedEntry = new WalletBatchEntry(wallet);

        log.info("Create initial credentials");
        final CredentialWithDeeplinkResponse offer = initializeCredentials(initialEntry);
        allCredentials.addAll(initialEntry.getIssuedCredentials());

        renewedEntry.setIssuerVCDeepLink(initialEntry.getIssuerVCDeepLink());
        renewedEntry.setCredentialOffer(initialEntry.getCredentialOffer());
        renewedEntry.setIssuerWellKnownConfiguration(initialEntry.getIssuerWellKnownConfiguration());
        renewedEntry.setIssuerMetadata(initialEntry.getIssuerMetadata());
        renewedEntry.setCredentialConfigurationSupported();
        renewedEntry.setToken(initialEntry.getToken());

        issuerManager.updateStateWithSignedJwt(
                jwtKey, "test-key-1",
                offer.getManagementId(),
                UpdateCredentialStatusRequestType.REVOKED
        );

        for (int i = 0; i < initialEntry.getIssuedCredentials().size(); i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(true)
                    .createManagementResponse();

            final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(toUri(verification.getVerificationDeeplink()));
            final String presentation = initialEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            log.info("Presenting credential from initial batch, which should be revoked " + presentation);
            final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
                wallet.respondToVerification(SwiyuApiVersionConfig.V1, verificationDetails, presentation);
            });
            ApiErrorAssert.assertThat(ex)
                    .hasError("invalid_transaction_data")
                    .hasErrorDescription("Credential has been Revoked!");
            verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
        }

        log.info("Retrieve a refresh token");
        String nonce = wallet.getCNonce(renewedEntry);
        String dpop = DPoPSupport.createDpopProofForToken(
                renewedEntry.getIssuerTokenUri().toString(), nonce, dpopKeyPair, dpopPublicKey,
                renewedEntry.getToken().getRefreshToken());
        final OAuthToken token = wallet.collectRefreshTokenWithDPoP(renewedEntry, dpop);
        renewedEntry.setToken(token);

        log.info("Generate proofs with a fresh nonce");
        nonce = wallet.getCNonce(renewedEntry);
        renewedEntry.generateHolderKeys();
        renewedEntry.createProofs(nonce);

        log.info("Renew credentials using the refresh token");
        nonce = wallet.getDpopNonce(renewedEntry);
        final String finalDpop = DPoPSupport.createDpopProofForToken(
                renewedEntry.getIssuerCredentialUri().toString(), nonce, dpopKeyPair, dpopPublicKey,
                token.getAccessToken());

        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
            wallet.postCredentialRequestWithRefreshToken(renewedEntry, token.getAccessToken(), finalDpop);
        });

        ApiErrorAssert.assertThat(ex)
                .hasError("invalid_transaction_data")
                .hasErrorDescription("Credential has been Revoked!");
    }

    @Test
    @XrayTest(
            key = "@TODO",
            summary = "All credentials (initial and renewed) are revoked and cannot be verified",
            description = """
                    This test validates the complete renewal and revocation flow where credentials are initially
                    issued, renewed through refresh token mechanism, and then all credentials (both initial batch
                    and renewed batch) are revoked by the credential management. The test ensures that revocation
                    is applied consistently to all credential batches and that verification fails for all revoked
                    credentials regardless of whether they are from the initial or renewed batch.
                    """)
    @Tag("@TODO")
    @Tag("happy_path")
    @DisableIfImageTag(
            issuer = {"stable", "staging", "rc", "dev"},
            reason = "This feature is not available yet"
    )
    void renewalFlow_whenSuspendedBeforeRenew_thenBothInitialAndRenewedRejected() {
        final List<String> allCredentials = new ArrayList<>();
        final WalletBatchEntry initialEntry = new WalletBatchEntry(wallet);
        final WalletBatchEntry renewedEntry = new WalletBatchEntry(wallet);

        log.info("Create initial credentials");
        final CredentialWithDeeplinkResponse offer = initializeCredentials(initialEntry);
        allCredentials.addAll(initialEntry.getIssuedCredentials());

        renewedEntry.setIssuerVCDeepLink(initialEntry.getIssuerVCDeepLink());
        renewedEntry.setCredentialOffer(initialEntry.getCredentialOffer());
        renewedEntry.setIssuerWellKnownConfiguration(initialEntry.getIssuerWellKnownConfiguration());
        renewedEntry.setIssuerMetadata(initialEntry.getIssuerMetadata());
        renewedEntry.setCredentialConfigurationSupported();
        renewedEntry.setToken(initialEntry.getToken());

        issuerManager.updateStateWithSignedJwt(
                jwtKey, "test-key-1",
                offer.getManagementId(),
                UpdateCredentialStatusRequestType.SUSPENDED
        );

        for (int i = 0; i < initialEntry.getIssuedCredentials().size(); i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(true)
                    .createManagementResponse();

            final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(toUri(verification.getVerificationDeeplink()));
            final String presentation = initialEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            log.info("Presenting credential from initial batch, which should be revoked " + presentation);
            final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
                wallet.respondToVerification(SwiyuApiVersionConfig.V1, verificationDetails, presentation);
            });
            ApiErrorAssert.assertThat(ex)
                    .hasError("invalid_transaction_data")
                    .hasErrorDescription("Credential has been Suspended!");
            verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
        }

        log.info("Retrieve a refresh token");
        String nonce = wallet.getCNonce(renewedEntry);
        String dpop = DPoPSupport.createDpopProofForToken(
                renewedEntry.getIssuerTokenUri().toString(), nonce, dpopKeyPair, dpopPublicKey,
                renewedEntry.getToken().getRefreshToken());
        final OAuthToken token = wallet.collectRefreshTokenWithDPoP(renewedEntry, dpop);
        renewedEntry.setToken(token);

        log.info("Generate proofs with a fresh nonce");
        nonce = wallet.getCNonce(renewedEntry);
        renewedEntry.generateHolderKeys();
        renewedEntry.createProofs(nonce);

        log.info("Renew credentials using the refresh token");
        nonce = wallet.getDpopNonce(renewedEntry);
        final String finalDpop = DPoPSupport.createDpopProofForToken(
                renewedEntry.getIssuerCredentialUri().toString(), nonce, dpopKeyPair, dpopPublicKey,
                token.getAccessToken());

        //final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
            wallet.postCredentialRequestWithRefreshToken(renewedEntry, token.getAccessToken(), finalDpop);
        //});

        //
        //ApiErrorAssert.assertThat(ex)
          //      .hasError("invalid_transaction_data")
            //    .hasErrorDescription("Credential has been Suspended!");

        for (int i = 0; i < renewedEntry.getIssuedCredentials().size(); i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(true)
                    .createManagementResponse();

            final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(toUri(verification.getVerificationDeeplink()));
            final String presentation = renewedEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            log.info("Presenting credential from initial batch, which should be revoked " + presentation);
            final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
                wallet.respondToVerification(SwiyuApiVersionConfig.V1, verificationDetails, presentation);
            });
            ApiErrorAssert.assertThat(ex)
                    .hasError("invalid_transaction_data")
                    .hasErrorDescription("Credential has been Suspended!");
            verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
        }
    }

}
