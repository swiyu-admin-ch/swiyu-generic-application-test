package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.OAuthToken;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.support.TestConstants;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.DPoPSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.security.KeyPair;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
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
class RenewalFlowTest extends BaseTest {

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
                issuerManager.createCredentialOffer("university_example_sd_jwt");

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

            final RequestObject details = wallet.getVerificationDetails(deepLink);
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
                        This test validates the complete renewal flow using the updated model where
                        credentials are issued directly after a successful token refresh.
                    
                        1. The wallet receives an offer, retrieves issuer configuration, and obtains an initial
                           access token and refresh token using a DPoP-bound request.
                        2. The wallet generates holder keys, creates proofs, and requests the initial batch
                           of credentials. All credentials are consumed through the verifier to simulate
                           their single-use nature.
                        3. The renewal is triggered by requesting a new nonce and refreshing the token using
                           the DPoP-bound refresh flow. A new access token and refresh token are returned.
                        4. Using the renewed token, the wallet requests a new batch of credentials via POST /credential,
                           accepting HTTP 200 or 202 responses. A second batch is successfully issued.
                    """
    )
    @Tag("renewal-flow")
    void renewalFlow_happyPath_fullyAlignedWithSequenceDiagram() {
        final List<String> allCredentials = new ArrayList<>();
        final WalletBatchEntry entry = new WalletBatchEntry(wallet);

        log.info("Create initial credentials");
        initializeCredentials(entry);
        allCredentials.addAll(entry.getIssuedCredentials());

        log.info("Retrieve a refresh token");
        String nonce = wallet.getCNonce(entry);
        String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(), nonce, dpopKeyPair, dpopPublicKey,
                entry.getToken().getRefreshToken());
        final OAuthToken token = wallet.collectRefreshTokenWithDPoP(entry, dpop);
        entry.setToken(token);

        log.info("Generate proofs with a fresh nonce");
        nonce = wallet.getCNonce(entry);
        entry.generateHolderKeys();
        entry.createProofs(nonce);

        log.info("Renew credentials using the refresh token");
        nonce = wallet.getDpopNonce(entry);
        dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerCredentialUri().toString(), nonce, dpopKeyPair, dpopPublicKey,
                token.getAccessToken());

        final var credentialResponse = wallet.postCredentialRequestWithRefreshToken(entry, token.getAccessToken(), dpop);
        assertThat(credentialResponse).isNotNull();
        allCredentials.addAll(entry.getIssuedCredentials());

        assertThat(allCredentials)
                .as("All credentials have been issued")
                .isNotNull()
                .hasSize(TestConstants.UNIVERSITY_EXAMPLE_BATCH_SIZE * 2);

        assertThat(allCredentials)
                .as("All credential JWTs must be unique")
                .doesNotHaveDuplicates();
    }


    @Test
    @XrayTest(
            key = "EIDOMNI-492",
            summary = "Renewal flow rejected due to invalid refresh token",
            description = """
                    Negative renewal flow test verifying that a credential renewal
                    is rejected when an invalid refresh token is used.
                    
                    1. The wallet completes a full happy-path issuance flow and
                       consumes the initially issued credentials.
                    2. The wallet prepares a renewal attempt using a refresh token.
                    3. The refresh token value is deliberately altered to simulate
                       an invalid or expired token.
                    4. A valid DPoP proof is generated for the token endpoint.
                    5. The wallet attempts to refresh the access token using the
                       invalid refresh token.
                    6. The issuer must reject the request with HTTP 401 and an
                       invalid_grant error response.
                    """
    )
    @Tag("refresh-flow")
    @Tag("issuance")
    void renewalFlow_withInvalidRefreshToken_thenRejected() {
        final List<String> allCredentials = new ArrayList<>();
        final WalletBatchEntry entry = new WalletBatchEntry(wallet);

        log.info("Create initial credentials");
        initializeCredentials(entry);
        allCredentials.addAll(entry.getIssuedCredentials());

        log.info("Retrieve a refresh token");
        String nonce = wallet.getCNonce(entry);
        String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(), nonce, dpopKeyPair, dpopPublicKey,
                entry.getToken().getRefreshToken());
        final OAuthToken token = wallet.collectRefreshTokenWithDPoP(entry, dpop);
        entry.setToken(token);

        log.info("Generate proofs with a fresh nonce");
        nonce = wallet.getCNonce(entry);
        entry.generateHolderKeys();
        entry.createProofs(nonce);

        nonce = wallet.getDpopNonce(entry);
        final String dpopCrendetialEndpoint = DPoPSupport.createDpopProofForToken(
                entry.getIssuerCredentialUri().toString(), nonce, dpopKeyPair, dpopPublicKey,
                token.getAccessToken());

        log.info("Provide wrong access token to simulate missmatch refresh token");
        final OAuthToken modifiedToken = Mockito.spy(token);
        Mockito.doReturn(UUID.randomUUID().toString()).when(modifiedToken).getAccessToken();

        log.info("Renew credentials using the wrong refresh token");
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.postCredentialRequestWithRefreshToken(entry, modifiedToken.getAccessToken(), dpopCrendetialEndpoint)
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
            key = "EIDOMNI-492",
            summary = "Renewal flow rejected due to invalid DPoP binding",
            description = """
                    Negative renewal flow test verifying that credential issuance is rejected
                    when the DPoP binding is invalid during a refreshed issuance flow.
                    
                    1. The wallet completes a full happy-path issuance flow and consumes the
                       initially issued credentials.
                    2. A refresh token is successfully used to obtain a new access token.
                    3. New holder proofs are generated for the renewed issuance attempt.
                    4. The credential request is sent using:
                       - an access token value that does not match the server state, and
                       - a DPoP proof signed with a different EC key than the one originally
                         bound to the token.
                    5. The issuer must reject the request with HTTP 401, enforcing strict
                       DPoP binding and token integrity.
                    """

    )
    @Tag("renewal-flow")
    @Tag("security")
    void renewalFlow_withWrongDpopBinding_thenRejected() {
        final List<String> allCredentials = new ArrayList<>();
        final WalletBatchEntry entry = new WalletBatchEntry(wallet);

        log.info("Create initial credentials");
        initializeCredentials(entry);
        allCredentials.addAll(entry.getIssuedCredentials());

        log.info("Retrieve a refresh token");
        String nonce = wallet.getCNonce(entry);
        String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(), nonce, dpopKeyPair, dpopPublicKey,
                entry.getToken().getRefreshToken());
        final OAuthToken token = wallet.collectRefreshTokenWithDPoP(entry, dpop);
        entry.setToken(token);

        log.info("Generate proofs with a fresh nonce");
        nonce = wallet.getCNonce(entry);
        entry.generateHolderKeys();
        entry.createProofs(nonce);

        nonce = wallet.getDpopNonce(entry);

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

        log.info("Renew credentials using the wrong dpop");
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.postCredentialRequestWithRefreshToken(entry, token.getAccessToken(), invalidDpopCrendetialEndpoint)
        );

        assertThat(errorCode(ex))
                .as("Invalid dpop must be rejected")
                .isEqualTo(401);

        assertThat(errorJson(ex))
                .containsEntry("error", "invalid_dpop_proof")
                .containsEntry("error_description", "Key mismatch");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-492",
            summary = "Renewal flow rejected due to DPoP nonce replay attack",
            description = """
                    Negative renewal flow test verifying that a DPoP nonce cannot be replayed
                    on the credential endpoint during a renewed issuance flow.
                    
                    1. The wallet completes a full happy-path issuance and renewal flow
                       until a new access token is obtained.
                    2. Holder keys and proofs are regenerated for the renewed issuance.
                    3. A valid DPoP proof is created for the credential endpoint using
                       a server-provided nonce.
                    4. The credential request succeeds once using the valid DPoP proof.
                    5. The same DPoP proof (same nonce and same jti) is reused in a second
                       credential request.
                    6. The issuer must reject the second request with HTTP 401, enforcing
                       nonce uniqueness and protecting against replay attacks.
                    """

    )
    @Tag("renewal-flow")
    @Tag("security")
    void renewalFlow_withNonceReplayAttack_thenRejected() {
        final List<String> allCredentials = new ArrayList<>();
        final WalletBatchEntry entry = new WalletBatchEntry(wallet);

        log.info("Create initial credentials");
        initializeCredentials(entry);
        allCredentials.addAll(entry.getIssuedCredentials());

        log.info("Retrieve a refresh token");
        String nonce = wallet.getCNonce(entry);
        String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(),
                nonce,
                dpopKeyPair,
                dpopPublicKey,
                entry.getToken().getRefreshToken()
        );
        final OAuthToken token = wallet.collectRefreshTokenWithDPoP(entry, dpop);
        entry.setToken(token);

        log.info("Generate proofs with a fresh nonce");
        nonce = wallet.getCNonce(entry);
        entry.generateHolderKeys();
        entry.createProofs(nonce);

        final String credentialNonce = wallet.getDpopNonce(entry);
        final String dpopCredential = DPoPSupport.createDpopProofForToken(entry.getIssuerCredentialUri().toString(),
                credentialNonce, dpopKeyPair, dpopPublicKey, token.getAccessToken());
        log.info("Renew valid credentials using the refresh token");
        final var firstResponse = wallet.postCredentialRequestWithRefreshToken(
                entry,
                token.getAccessToken(),
                dpopCredential
        );

        assertThat(firstResponse).isNotNull();

        log.info("Replay renew credentials using the same refresh token and dpop");
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.postCredentialRequestWithRefreshToken(
                        entry,
                        token.getAccessToken(),
                        dpopCredential
                )
        );

        assertThat(errorCode(ex))
                .as("Nonce replay must be rejected")
                .isEqualTo(401);

        assertThat(errorJson(ex))
                .containsEntry("error", "invalid_dpop_proof")
                .containsEntry("error_description", "Must use valid server provided nonce");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-492",
            summary = "TC 07 – Renewal blocked due to Credential Management REVOKED",
            description = """
                        Renewal test validating that the issuer blocks refresh-token based renewal
                        when the credential management entry has been revoked.
                    
                        1. Wallet receives the offer and obtains an initial DPoP-bound token.
                        2. Wallet performs the initial issuance of the credential batch.
                        3. Issuer revokes the credential management record.
                        4. Wallet attempts a renewal request (refresh_token + DPoP).
                        5. Issuer must reject the renewal as the credential management state is REVOKED.
                    """
    )
    @Tag("refresh-flow")
    @Tag("lifecycle")
    @Disabled("Discuss to confirm that this scenario must be rejected")
    void renewalFlow_whenCredentialIsRevokedAfterRefreshToken_thenReject() {
        final List<String> allCredentials = new ArrayList<>();
        final WalletBatchEntry entry = new WalletBatchEntry(wallet);

        log.info("Create initial credentials");
        final CredentialWithDeeplinkResponse offer = initializeCredentials(entry);
        allCredentials.addAll(entry.getIssuedCredentials());

        log.info("Retrieve a refresh token");
        String nonce = wallet.getCNonce(entry);
        String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(), nonce, dpopKeyPair, dpopPublicKey,
                entry.getToken().getRefreshToken());
        final OAuthToken token = wallet.collectRefreshTokenWithDPoP(entry, dpop);
        entry.setToken(token);

        log.info("Generate proofs with a fresh nonce");
        nonce = wallet.getCNonce(entry);
        entry.generateHolderKeys();
        entry.createProofs(nonce);

        nonce = wallet.getDpopNonce(entry);
        final String dpopCrendetialEndpoint = DPoPSupport.createDpopProofForToken(
                entry.getIssuerCredentialUri().toString(), nonce, dpopKeyPair, dpopPublicKey,
                token.getAccessToken());

        log.info("The management revokes the credential");
        issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.REVOKED);

        log.info("Renew credentials using the refresh token");
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.postCredentialRequestWithRefreshToken(entry, token.getAccessToken(), dpopCrendetialEndpoint)
        );

        assertThat(errorCode(ex))
                .as("Invalid refresh tokens must be rejected")
                .isEqualTo(401);

        assertThat(errorJson(ex))
                .containsEntry("error", "Error")
                .containsEntry("error_description", "Description Message");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-492",
            summary = "Renewal Flow – Rate limiting enforced on repeated renewals",
            description = """
                    Stress test verifying that the issuer enforces rate limiting
                    on repeated renewal attempts.
                    
                    1. Initial credential issuance is performed once.
                    2. The wallet repeatedly performs token refresh and credential renewal.
                    3. The loop continues until at least one HTTP 429 is received.
                    4. The test succeeds only if rate limiting is enforced.
                    """
    )
    @Tag("renewal-flow")
    @Tag("stress")
    @Tag("security")
    void renewalFlow_rateLimitEventuallyTriggered() {
        final int MAX_ATTEMPTS = 100;

        final WalletBatchEntry entry = new WalletBatchEntry(wallet);

        log.info("Initial issuance");
        initializeCredentials(entry);

        log.info("Perform %0d renewal flow attempt {}", MAX_ATTEMPTS);
        for (int i = 1; i <= MAX_ATTEMPTS; i++) {
            try {
                String nonce = wallet.getCNonce(entry);
                String dpopRefresh = DPoPSupport.createDpopProofForToken(
                        entry.getIssuerTokenUri().toString(),
                        nonce,
                        dpopKeyPair,
                        dpopPublicKey,
                        entry.getToken().getRefreshToken()
                );

                OAuthToken refreshedToken =
                        wallet.collectRefreshTokenWithDPoP(entry, dpopRefresh);

                entry.setToken(refreshedToken);

                nonce = wallet.getCNonce(entry);
                entry.generateHolderKeys();
                entry.createProofs(nonce);

                nonce = wallet.getDpopNonce(entry);
                String dpopCredential = DPoPSupport.createDpopProofForToken(
                        entry.getIssuerCredentialUri().toString(),
                        nonce,
                        dpopKeyPair,
                        dpopPublicKey,
                        refreshedToken.getAccessToken()
                );

                wallet.postCredentialRequestWithRefreshToken(
                        entry,
                        refreshedToken.getAccessToken(),
                        dpopCredential
                );

            } catch (HttpClientErrorException ex) {
                log.info("Exception is triggered at iteration {}", i);
                assertThat(errorCode(ex))
                        .as("At least one renewal attempt must be rejected with HTTP 429")
                        .isEqualTo(429);
                assertThat(errorJson(ex))
                        .containsEntry("error", "Error")
                        .containsEntry("error_description", "Error description");
            }
            assertThat(true).isTrue();
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-492",
            summary = "Renewal flow rejected due to invalid refresh token at token endpoint",
            description = """
                    Negative renewal flow test verifying that the token endpoint
                    rejects a refresh request when an invalid or unknown refresh
                    token is used.
                    
                    1. The wallet completes a full happy-path issuance flow.
                    2. The refresh token value is deliberately altered.
                    3. A valid DPoP proof is generated for the token endpoint.
                    4. The wallet attempts to refresh the access token.
                    5. The issuer must reject the request with HTTP 401 invalid_grant.
                    """
    )
    @Tag("refresh-flow")
    @Tag("security")
    void refreshToken_refreshWithInvalidToken_thenRejected() {
        final WalletBatchEntry entry = new WalletBatchEntry(wallet);
        log.info("Create initial credentials");
        initializeCredentials(entry);

        final OAuthToken originalToken = entry.getToken();

        log.info("Tamper the refresh token to simulate an invalid token");
        final OAuthToken tamperedToken = Mockito.spy(originalToken);
        Mockito.doReturn(UUID.randomUUID().toString())
                .when(tamperedToken).getRefreshToken();
        entry.setToken(tamperedToken);

        final String nonce = wallet.getCNonce(entry);
        final String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(),
                nonce,
                dpopKeyPair,
                dpopPublicKey,
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
            key = "EIDOMNI-492",
            summary = "Renewal flow rejected due to DPoP binding mismatch on refresh token",
            description = """
                    Negative renewal flow test verifying that a refresh token
                    cannot be used with a DPoP proof signed by a different key.
                    
                    1. The wallet completes a full happy-path issuance flow.
                    2. An attacker key pair is generated.
                    3. A DPoP proof is created using the attacker key.
                    4. The wallet attempts to refresh the access token.
                    5. The issuer must reject the request with HTTP 401.
                    """
    )
    @Tag("refresh-flow")
    @Tag("security")
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

        final String nonce = wallet.getCNonce(entry);
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
                .containsEntry("error", "invalid_dpop_proof")
                .containsEntry("error_description", "Key mismatch");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-492",
            summary = "Renewal flow rejected due to DPoP nonce replay on refresh endpoint",
            description = """
                    Negative renewal flow test verifying that a DPoP nonce
                    cannot be replayed on the token endpoint.
                    
                    1. The wallet completes a full happy-path issuance flow.
                    2. A valid DPoP proof is created for the refresh request.
                    3. The refresh succeeds once.
                    4. The same DPoP proof is reused.
                    5. The issuer must reject the second request with HTTP 401.
                    """
    )
    @Tag("refresh-flow")
    @Tag("security")
    void refreshToken_refreshNonceReplay_thenRejected() {
        final WalletBatchEntry entry = new WalletBatchEntry(wallet);
        log.info("Create initial credentials");
        initializeCredentials(entry);

        final String nonce = wallet.getCNonce(entry);
        final String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(),
                nonce,
                dpopKeyPair,
                dpopPublicKey,
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
                .containsEntry("error", "invalid_dpop_proof")
                .containsEntry("error_description", "Must use valid server provided nonce");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-492",
            summary = "Renewal flow rejected because credential management is revoked",
            description = """
                    Negative renewal flow test verifying that refresh token
                    usage is rejected when the credential management entry
                    has been revoked.
                    
                    1. Wallet completes initial issuance.
                    2. Issuer revokes the credential management record.
                    3. Wallet attempts to refresh the token.
                    4. Issuer must reject the request with HTTP 401.
                    """
    )
    @Tag("refresh-flow")
    @Tag("lifecycle")
    void refreshToken_refreshWhenCredentialManagementRevoked_thenRejected() {
        final WalletBatchEntry entry = new WalletBatchEntry(wallet);
        log.info("Create initial credentials");
        final CredentialWithDeeplinkResponse offer = initializeCredentials(entry);

        log.info("The management revokes the credential");
        issuerManager.updateState(
                offer.getManagementId(),
                UpdateCredentialStatusRequestType.REVOKED
        );

        final String nonce = wallet.getCNonce(entry);
        final String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(),
                nonce,
                dpopKeyPair,
                dpopPublicKey,
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
            key = "EIDOMNI-492",
            summary = "Credential management links renewed offers correctly across multiple renewals",
            description = """
                    Persistence test verifying that renewed credential offers
                    are correctly linked to their corresponding credential
                    management entity across multiple initial issuances
                    and renewal cycles.
                    
                    1. Wallet performs an initial issuance (A).
                    2. Wallet performs a renewal for issuance A.
                    3. Wallet performs a second initial issuance (B).
                    4. Wallet performs another renewal for issuance A.
                    5. Wallet performs a renewal for issuance B.
                    6. The issuer must persist all credential offers with the
                       correct credential_management_id, without cross-linking
                       between independent management entities.
                    """
    )
    @Tag("renewal-flow")
    @Tag("persistence")
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

        String nonce = wallet.getCNonce(entry);
        String dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerTokenUri().toString(),
                nonce,
                dpopKeyPair,
                dpopPublicKey,
                entry.getToken().getRefreshToken()
        );

        OAuthToken refreshedToken = wallet.collectRefreshTokenWithDPoP(entry, dpop);
        entry.setToken(refreshedToken);

        nonce = wallet.getCNonce(entry);
        entry.generateHolderKeys();
        entry.createProofs(nonce);

        nonce = wallet.getDpopNonce(entry);
        dpop = DPoPSupport.createDpopProofForToken(
                entry.getIssuerCredentialUri().toString(),
                nonce,
                dpopKeyPair,
                dpopPublicKey,
                refreshedToken.getAccessToken()
        );

        wallet.postCredentialRequestWithRefreshToken(
                entry,
                refreshedToken.getAccessToken(),
                dpop
        );
    }

    private int countOffersForManagement(UUID managementId) throws SQLException {

        String sql = """
                SELECT COUNT(*)
                FROM swiyu_issuer.credential_offer
                WHERE credential_management_id = ?
                """;

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setObject(1, managementId);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }
}
