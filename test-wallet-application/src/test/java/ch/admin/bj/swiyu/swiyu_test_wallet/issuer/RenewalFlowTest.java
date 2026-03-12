package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.OAuthToken;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.support.TestConstants;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.DPoPSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.HttpClientErrorException;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@ActiveProfiles({"issuer-strict"})
class RenewalFlowTest extends BaseTest {
    private static final String ERROR_INVALID_DPOP_PROOF = "invalid_dpop_proof";
    private static final String ERROR_KEY_MISSMATCH = "Key mismatch";

    @BeforeAll
    void setUp() {
        wallet.setUseDPoP(true);
    }

    private CredentialWithDeeplinkResponse initializeCredentials(WalletBatchEntry entry) {
        wallet.setUseDPoP(true);
        final CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialWithSignedJwt(jwtKey, keyId, CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);

        entry.receiveDeepLinkAndValidateIt(toUri(offer.getOfferDeeplink()));
        entry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(entry));
        entry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(entry));
        entry.setCredentialConfigurationSupported();

        final String nonceInitial = wallet.collectDPoPNonce(entry);
        final String tokenDPoP = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(), nonceInitial, wallet.getDpopKeyPair(), wallet.getDpopPublicKey()
        );
        entry.setToken(wallet.collectTokenWithDPoP(entry, tokenDPoP));
        
        entry.setCNonce(wallet.collectCNonce(entry));

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

            wallet.respondToVerificationV1(details, presentation);
            verifierManager.verifyState();
        }

        return offer;
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-492",
            summary = "Renewal Flow (Batch Issuance) – Happy Path",
            description = """
                    This test validates the complete renewal flow where a wallet successfully obtains
                    initial credentials and then renews the batch by refreshing the token and issuing
                    a second batch of credentials using the DPoP-bound refresh token mechanism.
                    """
    )
    @Tag(ReportingTags.UCI_C1)
    @Tag(ReportingTags.UCI_I2)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void renewalFlow_happyPath_fullyAlignedWithSequenceDiagram() {
        wallet.setUseDPoP(true);

        final WalletBatchEntry entry = new WalletBatchEntry(wallet);

        log.info("Create initial credentials");
        initializeCredentials(entry);

        log.info("Retrieve a refresh token");
        String nonce = wallet.collectCNonce(entry);
        String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(), nonce, wallet.getDpopKeyPair(), wallet.getDpopPublicKey(),
                entry.getToken().getRefreshToken());
        final OAuthToken token = wallet.collectRefreshTokenWithDPoP(entry, dpop);
        entry.setToken(token);
        entry.setCNonce(wallet.collectCNonce(entry));

        log.info("Generate proofs with a fresh nonce");
        entry.generateHolderKeys();
        entry.createProofs();

        final var credentialResponse = wallet.postCredentialRequest(entry);
        assertThat(credentialResponse).isNotNull();

        assertThat(entry.getIssuedCredentials())
                .as("All credentials have been issued")
                .isNotNull()
                .hasSize(TestConstants.UNIVERSITY_EXAMPLE_BATCH_SIZE * 2)
                .as("All credential JWTs must be unique")
                .doesNotHaveDuplicates();
    }


    @Test
    @XrayTest(
            key = "EIDOMNI-608",
            summary = "Renewal flow rejected due to invalid refresh token",
            description = """
                    This test validates that the renewal flow is rejected when an invalid or
                    tampered refresh token is used. The Issuer must enforce strict token
                    validation and deny requests with HTTP 400 invalid_token error.
                    """
    )
    @Tag(ReportingTags.UCI_C1)
    @Tag(ReportingTags.UCI_I2)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void renewalFlow_withInvalidRefreshToken_thenRejected() {
        final WalletBatchEntry entry = new WalletBatchEntry(wallet);

        log.info("Create initial credentials");
        initializeCredentials(entry);

        log.info("Retrieve a refresh token");
        String nonce = wallet.collectCNonce(entry);
        String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(), nonce, wallet.getDpopKeyPair(), wallet.getDpopPublicKey(),
                entry.getToken().getRefreshToken());
        final OAuthToken token = wallet.collectRefreshTokenWithDPoP(entry, dpop);
        entry.setToken(token);

        log.info("Generate proofs with a fresh nonce");
        nonce = wallet.collectCNonce(entry);
        entry.generateHolderKeys();
        entry.createProofs(nonce);

        nonce = wallet.collectDPoPNonce(entry);
        final String dpopCrendetialEndpoint = DPoPSupport.createDpopProofForToken(
                entry.getIssuerCredentialUri().toString(), nonce, wallet.getDpopKeyPair(), wallet.getDpopPublicKey(),
                token.getAccessToken());

        log.info("Provide wrong access token to simulate missmatch refresh token");
        final OAuthToken modifiedToken = Mockito.spy(token);
        doReturn(UUID.randomUUID().toString()).when(modifiedToken).getAccessToken();

        log.info("Renew credentials using the wrong refresh token");
        entry.setToken(modifiedToken);
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.postCredentialRequest(entry)
        );

        assertThat(errorCode(ex))
                .as("Invalid refresh token must be rejected")
                .isEqualTo(400);

        assertThat(errorJson(ex))
                .containsEntry("error", "INVALID_TOKEN")
                .containsEntry("error_description", "Invalid accessToken");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-609",
            summary = "Renewal flow rejected due to invalid DPoP binding",
            description = """
                    This test validates that credential renewal is rejected when the DPoP proof
                    is signed with a different cryptographic key than the one bound to the access token.
                    The Issuer must enforce strict DPoP binding verification and reject with HTTP 401.
                    """

    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.UCI_I1E)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void renewalFlow_withWrongDpopBinding_thenRejected() {
        final WalletBatchEntry entry = new WalletBatchEntry(wallet);

        log.info("Create initial credentials");
        initializeCredentials(entry);

        log.info("Retrieve a refresh token");
        String nonce = wallet.collectCNonce(entry);
        String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(), nonce, wallet.getDpopKeyPair(), wallet.getDpopPublicKey(),
                entry.getToken().getRefreshToken());
        final OAuthToken token = wallet.collectRefreshTokenWithDPoP(entry, dpop);
        entry.setToken(token);

        log.info("Generate proofs with a fresh nonce");
        nonce = wallet.collectCNonce(entry);
        entry.generateHolderKeys();
        entry.createProofs(nonce);

        nonce = wallet.collectDPoPNonce(entry);

        log.info("Provide wrong public key to simulate wrong dpop binding");
        final KeyPair attackerKeyPair = ECCryptoSupport.generateECKeyPair();
        final ECKey attackerPublicKey = new ECKey.Builder(
                Curve.P_256,
                (java.security.interfaces.ECPublicKey) attackerKeyPair.getPublic())
                .keyUse(KeyUse.SIGNATURE)
                .keyID("attacker-dpop-key-" + UUID.randomUUID())
                .build();
        final String invalidDpopCrendetialEndpoint = DPoPSupport.createDpopProofForToken(
                entry.getIssuerCredentialUri().toString(),
                nonce,
                attackerKeyPair,
                attackerPublicKey,
                token.getAccessToken()
        );

        final Wallet spyWallet = Mockito.spy(wallet);
        doReturn(invalidDpopCrendetialEndpoint)
                .when(spyWallet)
                .generateDpopForCredentialEndpoint(any());

        log.info("Renew credentials using the wrong dpop");
        final String accessToken = token.getAccessToken();
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> spyWallet.postCredentialRequest(entry)
        );

        assertThat(errorCode(ex))
                .as("Invalid dpop must be rejected")
                .isEqualTo(401);

        assertThat(errorJson(ex))
                .containsEntry("error", ERROR_INVALID_DPOP_PROOF)
                .containsEntry("error_description", ERROR_KEY_MISSMATCH);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-610",
            summary = "Renewal flow rejected due to DPoP nonce replay attack",
            description = """
                    This test validates that renewal requests are rejected when attempting to
                    replay the same DPoP proof with its nonce on the credential endpoint.
                    The Issuer must enforce nonce uniqueness and reject replayed requests with HTTP 401.
                    """

    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.UCI_I1E)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void renewalFlow_withNonceReplayAttack_thenRejected() {
        final WalletBatchEntry entry = new WalletBatchEntry(wallet);

        log.info("Create initial credentials");
        initializeCredentials(entry);

        log.info("Retrieve a refresh token");
        String nonce = wallet.collectCNonce(entry);
        String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(),
                nonce,
                wallet.getDpopKeyPair(),
                wallet.getDpopPublicKey(),
                entry.getToken().getRefreshToken()
        );
        final OAuthToken token = wallet.collectRefreshTokenWithDPoP(entry, dpop);
        entry.setToken(token);

        log.info("Generate proofs with a fresh nonce");
        nonce = wallet.collectCNonce(entry);
        entry.generateHolderKeys();
        entry.createProofs(nonce);

        final String credentialNonce = wallet.collectDPoPNonce(entry);
        final String dpopCredential = DPoPSupport.createDpopProofForToken(entry.getIssuerCredentialUri().toString(),
                credentialNonce, wallet.getDpopKeyPair(), wallet.getDpopPublicKey(), token.getAccessToken());
        log.info("Renew valid credentials using the refresh token");

        final Wallet spyWallet = Mockito.spy(wallet);
        doReturn(dpopCredential)
                .when(spyWallet)
                .generateDpopForCredentialEndpoint(any());

        final var firstResponse = spyWallet.postCredentialRequest(entry);

        assertThat(firstResponse).isNotNull();

        log.info("Replay renew credentials using the same refresh token and dpop");
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> spyWallet.postCredentialRequest(entry)
        );

        assertThat(errorCode(ex))
                .as("Nonce replay must be rejected")
                .isEqualTo(401);

        assertThat(errorJson(ex))
                .containsEntry("error", ERROR_INVALID_DPOP_PROOF)
                .containsEntry("error_description", "Must use valid server provided nonce");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-611",
            summary = "Renewal blocked due to Credential Management REVOKED",
            description = """
                    This test validates that the issuer blocks refresh-token based renewal
                    when the credential management entry has been revoked.
                    The renewal attempt must be rejected with HTTP 400 invalid_token error.
                    """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.UCI_I1E)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE, ImageTags.RC},
            reason = "This feature is not available yet"
    )
    void renewalFlow_whenCredentialIsRevokedAfterRefreshToken_thenReject() {
        final WalletBatchEntry entry = new WalletBatchEntry(wallet);

        log.info("Create initial credentials");
        final CredentialWithDeeplinkResponse offer = initializeCredentials(entry);

        log.info("Retrieve a refresh token");
        String nonce = wallet.collectCNonce(entry);
        String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(), nonce, wallet.getDpopKeyPair(), wallet.getDpopPublicKey(),
                entry.getToken().getRefreshToken());
        final OAuthToken token = wallet.collectRefreshTokenWithDPoP(entry, dpop);
        entry.setToken(token);

        log.info("Generate proofs with a fresh nonce");
        nonce = wallet.collectCNonce(entry);
        entry.generateHolderKeys();
        entry.createProofs(nonce);

        nonce = wallet.collectDPoPNonce(entry);
        final String dpopCrendetialEndpoint = DPoPSupport.createDpopProofForToken(
                entry.getIssuerCredentialUri().toString(), nonce, wallet.getDpopKeyPair(), wallet.getDpopPublicKey(),
                token.getAccessToken());

        log.info("The management revokes the credential");
        issuerManager.updateStateWithSignedJwt(
                jwtKey, keyId,
                offer.getManagementId(),
                UpdateCredentialStatusRequestType.REVOKED
        );

        log.info("Renew credentials using the refresh token");
        final String accessToken = token.getAccessToken();
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.postCredentialRequest(entry)
        );

        assertThat(errorCode(ex))
                .as("Invalid refresh tokens must be rejected")
                .isEqualTo(400);

        assertThat(errorJson(ex))
                .containsEntry("error_description", "Credential management is REVOKED, no renewal possible");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-612",
            summary = "Renewal flow rejected due to invalid refresh token at token endpoint",
            description = """
                    This test validates that the token endpoint rejects a refresh request
                    when an invalid or tampered refresh token is used. The Issuer must
                    enforce strict token validation and deny requests with HTTP 400 invalid_token error.
                    """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.UCI_I1E)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void refreshToken_refreshWithInvalidToken_thenRejected() {
        final WalletBatchEntry entry = new WalletBatchEntry(wallet);
        log.info("Create initial credentials");
        initializeCredentials(entry);

        final OAuthToken originalToken = entry.getToken();

        log.info("Tamper the refresh token to simulate an invalid token");
        final OAuthToken tamperedToken = Mockito.spy(originalToken);
        doReturn(UUID.randomUUID().toString())
                .when(tamperedToken).getRefreshToken();
        entry.setToken(tamperedToken);

        final String nonce = wallet.collectCNonce(entry);
        final String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(),
                nonce,
                wallet.getDpopKeyPair(),
                wallet.getDpopPublicKey(),
                tamperedToken.getRefreshToken()
        );

        log.info("Retrieve a refresh token");
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.collectRefreshTokenWithDPoP(entry, dpop)
        );

        assertThat(errorCode(ex)).isEqualTo(400);
        assertThat(errorJson(ex))
                .containsEntry("error", "INVALID_TOKEN")
                .containsEntry("error_description", "Invalid refresh token");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-613",
            summary = "Renewal flow rejected due to DPoP binding mismatch on refresh token",
            description = """
                    This test validates that a refresh token cannot be used with a DPoP proof
                    signed by a different cryptographic key. The issuer must enforce strict
                    DPoP binding verification and reject with HTTP 401.
                    """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.UCI_I1E)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void refreshToken_refreshWithWrongDpopBinding_thenRejected() {
        final WalletBatchEntry entry = new WalletBatchEntry(wallet);
        log.info("Create initial credentials");
        initializeCredentials(entry);

        log.info("Tamper the dpop to simulate an invalid binding");
        final KeyPair attackerKeyPair = ECCryptoSupport.generateECKeyPair();
        final ECKey attackerPublicKey = new ECKey.Builder(
                Curve.P_256,
                (java.security.interfaces.ECPublicKey) attackerKeyPair.getPublic())
                .keyUse(KeyUse.SIGNATURE)
                .keyID("attacker-dpop-" + UUID.randomUUID())
                .build();

        final String nonce = wallet.collectCNonce(entry);
        final String invalidDpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(),
                nonce,
                attackerKeyPair,
                attackerPublicKey,
                entry.getToken().getRefreshToken()
        );

        log.info("Retrieve a refresh token");
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.collectRefreshTokenWithDPoP(entry, invalidDpop)
        );

        assertThat(errorJson(ex))
                .containsEntry("error", ERROR_INVALID_DPOP_PROOF)
                .containsEntry("error_description", ERROR_KEY_MISSMATCH);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-614",
            summary = "Renewal flow rejected due to DPoP nonce replay on refresh endpoint",
            description = """
                    This test validates that a DPoP nonce cannot be replayed on the token endpoint.
                    The issuer must enforce nonce uniqueness and reject replayed refresh requests
                    with HTTP 401.
                    """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.UCI_I1E)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "(Stable) This feature is not available yet (Staging) This was fixed on next versions"
    )
    void refreshToken_refreshNonceReplay_thenRejected() {
        final WalletBatchEntry entry = new WalletBatchEntry(wallet);
        log.info("Create initial credentials");
        initializeCredentials(entry);

        final String nonce = wallet.collectCNonce(entry);
        final String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(),
                nonce,
                wallet.getDpopKeyPair(),
                wallet.getDpopPublicKey(),
                entry.getToken().getRefreshToken()
        );

        log.info("Retrieve a refresh token");
        final OAuthToken refreshed = wallet.collectRefreshTokenWithDPoP(entry, dpop);
        assertThat(refreshed).isNotNull();

        log.info("Replay the refresh token request with the same dpop");
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.collectRefreshTokenWithDPoP(entry, dpop)
        );

        assertThat(errorCode(ex)).isEqualTo(401);
        assertThat(errorJson(ex))
                .containsEntry("error", ERROR_INVALID_DPOP_PROOF)
                .containsEntry("error_description", "Must use valid server provided nonce");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-615",
            summary = "Renewal flow rejected because credential management is revoked",
            description = """
                    This test validates that refresh token usage is rejected when the credential 
                    management entry has been revoked. The issuer must block token refresh attempts
                    and return HTTP 400 invalid_token error.
                    """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.UCI_I1E)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "(Stable) This feature is not available yet (Staging) This was fixed on next versions"
    )
    void refreshToken_refreshWhenCredentialManagementRevoked_thenRejected() {
        final WalletBatchEntry entry = new WalletBatchEntry(wallet);
        log.info("Create initial credentials");
        final CredentialWithDeeplinkResponse offer = initializeCredentials(entry);

        log.info("The management revokes the credential");
        issuerManager.updateStateWithSignedJwt(
                jwtKey, keyId,
                offer.getManagementId(),
                UpdateCredentialStatusRequestType.REVOKED
        );

        final String nonce = wallet.collectCNonce(entry);
        final String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(),
                nonce,
                wallet.getDpopKeyPair(),
                wallet.getDpopPublicKey(),
                entry.getToken().getRefreshToken()
        );

        log.info("Retrieve a refresh token");
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.collectRefreshTokenWithDPoP(entry, dpop)
        );

        assertThat(errorCode(ex)).isEqualTo(400);
        assertThat(errorJson(ex))
                .containsEntry("error", "INVALID_TOKEN")
                .containsEntry("error_description", "Invalid refresh token");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-616",
            summary = "Credential management links renewed offers correctly across multiple renewals",
            description = """
                    This test validates that renewed credential offers are correctly linked 
                    to their corresponding credential management entity across multiple initial 
                    issuances and renewal cycles. Each credential offer must retain the correct 
                    credential_management_id without cross-linking between independent management entities.
                    """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.UCI_I1E)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void credentialManagement_shouldLinkRenewalsCorrectly_acrossMultipleInitialOffers() throws Exception {

        log.info("Create initial credentials for issuance A");
        WalletBatchEntry entryA = new WalletBatchEntry(wallet);
        final CredentialWithDeeplinkResponse offerA = initializeCredentials(entryA);
        final UUID managementA = offerA.getManagementId();

        assertThat(countOffersForManagement(managementA))
                .as("Initial issuance A must create exactly one credential offer")
                .isEqualTo(1);

        log.info("Perform first renewal for issuance A");
        performRefresh(entryA);

        assertThat(countOffersForManagement(managementA))
                .as("First renewal of A must create a second credential offer linked to the same management")
                .isEqualTo(2);

        log.info("Create initial credentials for issuance B");
        WalletBatchEntry entryB = new WalletBatchEntry(wallet);
        final CredentialWithDeeplinkResponse offerB = initializeCredentials(entryB);
        final UUID managementB = offerB.getManagementId();

        assertThat(countOffersForManagement(managementB))
                .as("Initial issuance B must create exactly one credential offer")
                .isEqualTo(1);

        log.info("Perform second renewal for issuance A");
        performRefresh(entryA);

        assertThat(countOffersForManagement(managementA))
                .as("Second renewal of A must create a third credential offer linked to management A")
                .isEqualTo(3);

        assertThat(countOffersForManagement(managementB))
                .as("Renewals of A must not affect credential offers linked to management B")
                .isEqualTo(1);

        log.info("Perform renewal for issuance B");
        performRefresh(entryB);

        assertThat(countOffersForManagement(managementA))
                .as("Management A must contain exactly three credential offers after two renewals")
                .isEqualTo(3);

        assertThat(countOffersForManagement(managementB))
                .as("Management B must contain exactly two credential offers after one renewal")
                .isEqualTo(2);
    }

    private void performRefresh(WalletBatchEntry entry) {
        String nonce = wallet.collectCNonce(entry);
        String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(),
                nonce,
                wallet.getDpopKeyPair(),
                wallet.getDpopPublicKey(),
                entry.getToken().getRefreshToken()
        );

        OAuthToken refreshedToken = wallet.collectRefreshTokenWithDPoP(entry, dpop);
        entry.setToken(refreshedToken);

        nonce = wallet.collectCNonce(entry);
        entry.generateHolderKeys();
        entry.createProofs(nonce);

        nonce = wallet.collectDPoPNonce(entry);
        dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerCredentialUri().toString(),
                nonce,
                wallet.getDpopKeyPair(),
                wallet.getDpopPublicKey(),
                refreshedToken.getAccessToken()
        );

        wallet.postCredentialRequest(entry);
    }

    private int countOffersForManagement(UUID managementId) throws SQLException {

        final String sql = """
                SELECT COUNT(*)
                FROM %s.credential_offer
                WHERE credential_management_id = ?
                """.formatted(issuerImageConfig.getDbSchema());

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setObject(1, managementId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    throw new NoSuchElementException(
                            "No result found for managementId=" + managementId
                    );
                }
                final int result = rs.getInt(1);
                if (rs.next()) {
                    throw new IllegalStateException(
                            "Multiple results found for managementId=" + managementId
                    );
                }

                return result;
            }
        }
    }
}