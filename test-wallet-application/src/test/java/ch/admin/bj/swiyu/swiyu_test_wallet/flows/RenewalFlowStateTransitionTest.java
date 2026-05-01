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
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
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
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@ActiveProfiles({"issuer-strict"})
public class RenewalFlowStateTransitionTest extends BaseTest {

    @BeforeAll
    void setUp() {
        wallet.setUseDPoP(true);
    }

    private CredentialWithDeeplinkResponse initializeCredentials(final WalletBatchEntry entry) {
        final CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialWithSignedJwt(jwtKey, "test-key-1", CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);

        entry.receiveDeepLinkAndValidateIt(toUri(offer.getOfferDeeplink()));
        entry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(entry));
        entry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(entry));
        entry.setCredentialConfigurationSupported();

        final String nonceInitial = wallet.collectDPoPNonce(entry);

        final String dpopInitial = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(), nonceInitial, wallet.getDpopKeyPair(), wallet.getDpopPublicKey());

        final OAuthToken token1 = wallet.collectTokenWithDPoP(entry, dpopInitial);
        entry.setToken(token1);
        entry.setCNonce(wallet.collectDPoPNonce(entry));

        entry.generateHolderKeys();
        entry.createProofs();

        final var credentialResponseRenewal = wallet.postCredentialRequest(entry);
        assertThat(credentialResponseRenewal).isNotNull();
        final List<String> batch1 = entry.getIssuedCredentials();

        for (int i = 0; i < batch1.size(); i++) {
            final String deepLink = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL()
                    .create();

            final RequestObject details = wallet.getVerificationDetailsUnsigned(deepLink);
            final String presentation = entry.createPresentationForSdJwtIndex(i, details);

            wallet.respondToVerification(details, presentation);
            verifierManager.verifyState();
        }

        return offer;
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-713",
            summary = "Revocation applies to both initial and renewed credentials in OID4VP flow",
            description = """
                    This test validates that when an Issuer revokes a credential after it has been renewed,
                    the revocation applies to all related credential batches.
                    
                    The Issuer first issues a batch of credentials. The Wallet then renews the credentials
                    using the refresh token mechanism, resulting in a second batch of valid credentials.
                    
                    When the Issuer revokes the credential through the management endpoint, both the
                    initial batch and the renewed batch must be considered revoked.
                    
                    Any attempt by the Wallet to present credentials from either batch in an OID4VP
                    verification flow must be rejected by the Verifier.
                    """)
    @Tag("ucv_c3")
    @Tag("ucv_o2c")
    @Tag("edge_case")
    @DisableIfImageTag(
            issuer = {"stable", "staging", "rc"},
            reason = "This fix is not available yet"
    )
    void credentialRenewal_whenRevoked_thenAllCredentialsAreRejected() {
        // Given
        final UpdateCredentialStatusRequestType updateStatus = UpdateCredentialStatusRequestType.REVOKED;

        final WalletBatchEntry initialEntry = new WalletBatchEntry(wallet);
        final CredentialWithDeeplinkResponse offer = initializeCredentials(initialEntry);
        final WalletBatchEntry renewedEntry = initialEntry.duplicate();

        // When - Renew credentials
        String nonce = wallet.collectCNonce(renewedEntry);
        renewedEntry.generateHolderKeys();
        renewedEntry.createProofs(nonce);

        nonce = wallet.collectDPoPNonce(renewedEntry);
        final String finalDpop = DPoPSupport.createDpopProofForToken(
                renewedEntry.getIssuerCredentialUri().toString(), nonce, wallet.getDpopKeyPair(), wallet.getDpopPublicKey(),
                renewedEntry.getToken().getAccessToken());

        final var credentialResponse = wallet.postCredentialRequest(renewedEntry);

        // Then - Wallet was able to successfully renew credentials in another batch
        assertThat(credentialResponse).isNotNull();
        List<String> all = Stream.concat(initialEntry.getIssuedCredentials().stream(), renewedEntry.getIssuedCredentials().stream()).toList();
        SdJwtBatchAssert.assertThat(all)
                .areUnique()
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE * 2);


        // When - Revoke both initial and renewed credentials
        issuerManager.updateStateWithSignedJwt(
                jwtKey, "test-key-1",
                offer.getManagementId(),
                updateStatus
        );

        // Then - Verify that initial credentials cannot be verified
        for (int i = 0; i < initialEntry.getIssuedCredentials().size(); i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(true)
                    .createManagementResponse();

            final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
            final String presentation = initialEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
                wallet.respondToVerification(verificationDetails, presentation);
            });
            ApiErrorAssert.assertThat(ex)
                    .hasError("invalid_transaction_data")
                    .hasErrorDescription("Credential has been Revoked!");
            verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
        }

        // Then - Verify that renewed credentials cannot be verified
        for (int i = 0; i < renewedEntry.getIssuedCredentials().size(); i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(true)
                    .createManagementResponse();

            final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
            final String presentation = renewedEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
                wallet.respondToVerification(verificationDetails, presentation);
            });
            ApiErrorAssert.assertThat(ex)
                    .hasError("invalid_transaction_data")
                    .hasErrorDescription("Credential has been Revoked!");
            verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-714",
            summary = "Suspension applies to both initial and renewed credentials until reactivation in OID4VP flow",
            description = """
                    This test validates that when an Issuer suspends a credential after it has been renewed,
                    the suspension applies to all related credential batches managed under the same offer.
                    
                    The Issuer first issues a batch of credentials associated with a management offer.
                    The Wallet then renews the credentials using the refresh token mechanism, creating
                    a renewed batch linked to the same management context.
                    
                    When the Issuer suspends the credential via the management endpoint, both the
                    initial batch and the renewed batch must be considered suspended.
                    
                    Any attempt by the Wallet to present credentials from either batch in an OID4VP
                    verification flow must be rejected by the Verifier.
                    
                    Once the Issuer reactivates the credential by setting the status back to ISSUED,
                    the Wallet must be able to successfully complete the OID4VP verification flow.
                    """)
    @Tag("ucv_c3")
    @Tag("ucv_o2c")
    @Tag("edge_case")
    @DisableIfImageTag(
            issuer = {"stable", "staging", "rc"},
            reason = "This fix is not available yet"
    )
    void credentialRenewal_whenSuspended_thenAllCredentialsAreRejected() {
        // Given
        wallet.setUseDPoP(true);

        final UpdateCredentialStatusRequestType updateStatus = UpdateCredentialStatusRequestType.SUSPENDED;

        final WalletBatchEntry initialEntry = new WalletBatchEntry(wallet);
        final CredentialWithDeeplinkResponse offer = initializeCredentials(initialEntry);
        final WalletBatchEntry renewedEntry = initialEntry.duplicate();

        // When - Renew credentials
        String nonce = wallet.collectCNonce(renewedEntry);
        renewedEntry.generateHolderKeys();
        renewedEntry.createProofs(nonce);

        final var credentialResponse = wallet.postCredentialRequest(renewedEntry);

        // Then - Wallet was able to successfully renew credentials in another batch
        assertThat(credentialResponse).isNotNull();
        List<String> all = Stream.concat(initialEntry.getIssuedCredentials().stream(), renewedEntry.getIssuedCredentials().stream()).toList();
        SdJwtBatchAssert.assertThat(all)
                .areUnique()
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE * 2);

        // When - Suspend both initial and renewed credentials
        issuerManager.updateStateWithSignedJwt(
                jwtKey, "test-key-1",
                offer.getManagementId(),
                updateStatus
        );

        // Then - Verify that initial credentials cannot be verified
        for (int i = 0; i < initialEntry.getIssuedCredentials().size(); i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(true)
                    .createManagementResponse();

            final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
            final String presentation = initialEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
                wallet.respondToVerification(verificationDetails, presentation);
            });
            ApiErrorAssert.assertThat(ex)
                    .hasError("invalid_transaction_data")
                    .hasErrorDescription("Credential has been Suspended!");
            verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
        }

        // Then - Verify that renewed credentials cannot be verified
        for (int i = 0; i < renewedEntry.getIssuedCredentials().size(); i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(true)
                    .createManagementResponse();

            final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
            final String presentation = renewedEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
                wallet.respondToVerification(verificationDetails, presentation);
            });
            ApiErrorAssert.assertThat(ex)
                    .hasError("invalid_transaction_data")
                    .hasErrorDescription("Credential has been Suspended!");
            verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
        }

        // When - Reactivate credentials by setting status back to ISSUED
        issuerManager.updateStateWithSignedJwt(
                jwtKey, "test-key-1",
                offer.getManagementId(),
                UpdateCredentialStatusRequestType.ISSUED
        );

        // Then - Verify that both initial and renewed credentials can now be verified successfully
        for (int i = 0; i < initialEntry.getIssuedCredentials().size(); i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(true)
                    .createManagementResponse();

            final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
            final String presentation = initialEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            wallet.respondToVerification(verificationDetails, presentation);
            verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
        }

        for (int i = 0; i < renewedEntry.getIssuedCredentials().size(); i++) {
            final ManagementResponse verification = verifierManager.verificationRequest()
                    .acceptedIssuerDid(issuerConfig.getIssuerDid())
                    .withUniversityDCQL(true)
                    .createManagementResponse();

            final RequestObject verificationDetails = wallet.getVerificationDetailsUnsigned(verification.getVerificationDeeplink());
            final String presentation = renewedEntry.createPresentationForSdJwtIndex(i, verificationDetails);
            wallet.respondToVerification(verificationDetails, presentation);
            verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-715",
            summary = "Revoked credentials cannot be renewed through the renewal flow",
            description = """
                    This test validates that once a credential associated with a management offer
                    has been revoked by the Issuer, it is no longer possible to renew it.
                    
                    The Issuer first issues a batch of credentials under a management offer.
                    The Issuer then revokes the credential before any renewal occurs.
                    
                    When the Wallet attempts to initiate a renewal flow using the refresh token,
                    the renewal request must be rejected and no new credential batch must be issued.
                    
                    A revoked credential must permanently terminate the lifecycle of the
                    associated offer and prevent any further renewal operations.
                    """
    )
    @Tag("ucv_c3")
    @Tag("ucv_o2c")
    @Tag("edge_case")
    @DisableIfImageTag(
            issuer = {"stable", "staging", "rc"},
            reason = "This fix is not available yet"
    )
    void credentialRenewal_whenRevokedBeforeRenewal_thenRenewalIsRejected() {
        // Given
        final UpdateCredentialStatusRequestType updateStatus = UpdateCredentialStatusRequestType.REVOKED;

        final WalletBatchEntry initialEntry = new WalletBatchEntry(wallet);
        final CredentialWithDeeplinkResponse offer = initializeCredentials(initialEntry);
        final WalletBatchEntry renewedEntry = initialEntry.duplicate();

        // When - Revoke credentials before renewal attempt
        issuerManager.updateStateWithSignedJwt(
                jwtKey, "test-key-1",
                offer.getManagementId(),
                updateStatus
        );

        // When - Attempt to renew revoked credentials
        String nonce = wallet.collectCNonce(renewedEntry);
        renewedEntry.generateHolderKeys();
        renewedEntry.createProofs(nonce);

        nonce = wallet.collectDPoPNonce(renewedEntry);
        final String finalDpop = DPoPSupport.createDpopProofForToken(
                renewedEntry.getIssuerCredentialUri().toString(), nonce, wallet.getDpopKeyPair(), wallet.getDpopPublicKey(),
                renewedEntry.getToken().getAccessToken());

        // Then - Renewal must be rejected
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
            wallet.postCredentialRequest(renewedEntry);
        });

        ApiErrorAssert.assertThat(ex)
                .hasErrorDescription("Credential management is REVOKED, no renewal possible");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-716",
            summary = "Suspended credentials cannot produce valid renewed credentials",
            description = """
                    This test validates that when a credential associated with a management offer
                    is suspended before a renewal flow, the suspension prevents the issuance of
                    valid renewed credentials.
                    
                    The Issuer first issues a batch of credentials under a management offer.
                    The Issuer then suspends the credential before the Wallet initiates the
                    renewal process.
                    
                    When the Wallet attempts to renew the credential using the refresh token,
                    the system must not issue a new valid credential batch.
                    
                    Suspension must prevent the lifecycle from progressing through renewal
                    until the Issuer explicitly reactivates the credential.
                    """
    )
    @Tag("ucv_c3")
    @Tag("ucv_o2c")
    @Tag("edge_case")
    @DisableIfImageTag(
            issuer = {"stable", "staging", "rc"},
            reason = "This fix is not available yet"
    )
    void credentialRenewal_whenSuspendedBeforeRenewal_thenNoValidRenewedCredentialsAreIssued() {
        // Given
        final UpdateCredentialStatusRequestType updateStatus = UpdateCredentialStatusRequestType.SUSPENDED;

        final WalletBatchEntry initialEntry = new WalletBatchEntry(wallet);
        final CredentialWithDeeplinkResponse offer = initializeCredentials(initialEntry);
        final WalletBatchEntry renewedEntry = initialEntry.duplicate();

        // When - Revoke credentials before renewal attempt
        issuerManager.updateStateWithSignedJwt(
                jwtKey, "test-key-1",
                offer.getManagementId(),
                updateStatus
        );

        // When - Attempt to renew suspended credentials
        String nonce = wallet.collectCNonce(renewedEntry);
        renewedEntry.generateHolderKeys();
        renewedEntry.createProofs(nonce);

        nonce = wallet.collectDPoPNonce(renewedEntry);
        final String finalDpop = DPoPSupport.createDpopProofForToken(
                renewedEntry.getIssuerCredentialUri().toString(), nonce, wallet.getDpopKeyPair(), wallet.getDpopPublicKey(),
                renewedEntry.getToken().getAccessToken());

        // Then - Renewal must be rejected
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
            wallet.postCredentialRequest(renewedEntry);
        });

        ApiErrorAssert.assertThat(ex)
                .hasErrorDescription("Credential management is SUSPENDED, no renewal possible");
    }
}
