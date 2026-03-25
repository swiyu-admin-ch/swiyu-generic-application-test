package ch.admin.bj.swiyu.swiyu_test_wallet.security;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.OAuthToken;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.JwtProof;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.net.URI;
import java.security.KeyPair;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class DPoPFlowTest extends BaseTest {
    @BeforeAll
    void setUp() {
        wallet.setUseDPoP(true);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-428",
            summary = "DPoP – Token request and credential request are protected with DPoP",
            description = """
                    This test verifies the basic DPoP flow for initial issuance:
                    1. Wallet receives a credential offer (pre-authorized code).
                    2. Wallet obtains (optionally) a nonce for DPoP from the nonce endpoint.
                    3. Wallet creates a DPoP proof JWT for the token endpoint (htm POST, htu /token).
                    4. Wallet calls /token with DPoP header and pre-authorized_code.
                    5. Issuer returns an access_token with token_type "DPoP".
                    6. Wallet uses that access_token to call /credential (V1) – Wallet will attach a DPoP proof.
                    7. Issuer successfully issues credentials.
                    """
    )
    @Tag(ReportingTags.UCI_C1)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void dpopInitialIssuance_happyPath() {
        CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        assertThat(offer).isNotNull();
        assertThat(offer.getOfferDeeplink()).isNotBlank();

        URI deeplink = wallet.getIssuerContext()
                .getContextualizedUri(toUri(offer.getOfferDeeplink()));

        WalletBatchEntry batchEntry = new WalletBatchEntry(wallet);
        batchEntry.receiveDeepLinkAndValidateIt(deeplink);
        batchEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(batchEntry));
        batchEntry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(batchEntry));
        batchEntry.setCredentialConfigurationSupported();

        log.info("Wallet obtains DPoP nonce from /nonce endpoint");
        String dpopNonce = wallet.collectDPoPNonce(batchEntry);
        assertThat(dpopNonce).isNotBlank();

        log.info("Wallet creates DPoP proof for token endpoint");
        URI tokenUri = batchEntry.getIssuerTokenUri();
        String dpopProofForToken = createDpopProofForToken(tokenUri.toString(), "POST", dpopNonce);

        log.info("Wallet sends token request with DPoP header and pre-authorized code");
        OAuthToken token = wallet.collectTokenWithDPoP(batchEntry, dpopProofForToken);
        assertThat(token).isNotNull();
        assertThat(token.getAccessToken()).isNotBlank();
        assertThat(token.getTokenType()).isEqualTo("DPoP");
        log.info("Issuer responds with access_token (type=DPoP) and ready for batch issuance");

        batchEntry.setToken(token);
        batchEntry.setCNonce(wallet.collectCNonce(batchEntry));

        final int batchSize = batchEntry.getIssuerMetadata().getBatchCredentialIssuance().getBatchSize();

        log.info("Wallet generates {} holder keys and creates proofs", batchSize);
        batchEntry.generateHolderKeys();
        batchEntry.createProofs();

        log.info("Wallet sends credential request with DPoP proof for batch of {}", batchSize);
        var issuedCredentials = wallet.getVerifiableCredentialFromIssuer(batchEntry);

        assertThat(issuedCredentials)
                .as("Issuer should return a batch of %s credentials", batchSize)
                .hasSize(batchSize);

        issuedCredentials.forEach(cred ->
                assertThat(cred)
                        .as("Each issued credential must be a non-empty SD-JWT")
                        .isNotNull()
                        .isNotBlank());

        log.info("Issuer successfully issued batch of {} credentials", batchSize);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-481",
            summary = "DPoP – Refresh token flow with nonce and DPoP proof",
            description = """
                    This test verifies the DPoP-based refresh flow:
                    
                    1. Wallet receives a credential offer (pre-authorized code).
                    2. Wallet requests a DPoP nonce from /nonce.
                    3. Wallet creates a DPoP proof JWT for the token endpoint (htm POST, htu /token).
                    4. Wallet calls /token with grant_type=pre-authorized_code and DPoP header.
                    5. Issuer returns access_token + refresh_token.
                    6. Wallet requests a new DPoP nonce from /nonce for the refresh flow.
                    7. Wallet creates a new DPoP proof JWT for the token endpoint (refresh).
                    8. Wallet calls /token with grant_type=refresh_token, refresh_token and DPoP header.
                    9. Issuer returns a new access_token and refresh_token.
                    10. Wallet uses the refreshed access_token on /credential (V1) and receives credentials.
                    """
    )
    @Tag(ReportingTags.UCI_C1)
    @Tag(ReportingTags.UCI_I2)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void dpopRefreshFlow_happyPath() {
        CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialOffer("bound_example_sd_jwt");
        assertThat(offer).isNotNull();
        assertThat(offer.getOfferDeeplink()).isNotBlank();

        URI deeplink = wallet.getIssuerContext()
                .getContextualizedUri(toUri(offer.getOfferDeeplink()));

        WalletBatchEntry batchEntry = new WalletBatchEntry(wallet);
        batchEntry.receiveDeepLinkAndValidateIt(deeplink);
        batchEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(batchEntry));
        batchEntry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(batchEntry));
        batchEntry.setCredentialConfigurationSupported();

        log.info("Wallet requests initial token with pre-authorized code and DPoP proof");
        String initialDpopNonce = wallet.collectDPoPNonce(batchEntry);
        assertThat(initialDpopNonce).isNotBlank();

        URI tokenUri = batchEntry.getIssuerTokenUri();
        String initialDpopProof = createDpopProofForToken(tokenUri.toString(), "POST", initialDpopNonce);

        OAuthToken initialToken = wallet.collectTokenWithDPoP(batchEntry, initialDpopProof);
        assertThat(initialToken).isNotNull();
        assertThat(initialToken.getAccessToken()).isNotBlank();
        assertThat(initialToken.getRefreshToken()).isNotBlank();
        assertThat(initialToken.getTokenType()).isEqualTo("DPoP");
        log.info("Issuer issues initial token with refresh_token capability");

        batchEntry.setToken(initialToken);
        String initialAccessToken = initialToken.getAccessToken();
        String initialRefreshToken = initialToken.getRefreshToken();

        log.info("Wallet requests new nonce for refresh operation");
        String refreshDpopNonce = wallet.collectDPoPNonce(batchEntry);
        assertThat(refreshDpopNonce).isNotBlank();

        log.info("Wallet sends refresh_token request with new DPoP proof");
        String refreshDpopProof = createDpopProofForToken(tokenUri.toString(), "POST", refreshDpopNonce);

        OAuthToken refreshedToken = wallet.refreshTokenWithDPoP(batchEntry, refreshDpopProof);
        assertThat(refreshedToken).isNotNull();
        assertThat(refreshedToken.getAccessToken()).isNotBlank();
        assertThat(refreshedToken.getRefreshToken()).isNotBlank();
        log.info("Issuer refreshes tokens successfully");

        assertThat(refreshedToken.getAccessToken())
                .as("Refreshed access token must differ from initial")
                .isNotEqualTo(initialAccessToken);

        assertThat(refreshedToken.getRefreshToken())
                .as("Refreshed refresh token must differ from initial")
                .isNotEqualTo(initialRefreshToken);

        batchEntry.setToken(refreshedToken);
        batchEntry.setCNonce(wallet.collectCNonce(batchEntry));


        log.info("Wallet generates {} holder keys for credential renewal", CredentialConfigurationFixtures.BATCH_SIZE);
        batchEntry.generateHolderKeys();
        batchEntry.createProofs();

        log.info("Wallet requests batch of {} credentials with refreshed token", CredentialConfigurationFixtures.BATCH_SIZE);
        var refreshedCredentials = wallet.getVerifiableCredentialFromIssuer(batchEntry);

        assertThat(refreshedCredentials)
                .as("Issuer should return a batch of %s credentials using refreshed token", CredentialConfigurationFixtures.BATCH_SIZE)
                .hasSize(CredentialConfigurationFixtures.BATCH_SIZE);

        refreshedCredentials.forEach(cred ->
                assertThat(cred)
                        .as("Each issued credential after refresh must be a non-empty SD-JWT")
                        .isNotNull()
                        .isNotBlank());

        log.info("Token renewal flow completed successfully");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-482",
            summary = "Vulnerability Check: DPoP Nonce Invalidation After Usage",
            description = """
                    This test verifies that the vulnerability "Nonce not invalidated after DPoP usage" 
                    has been fixed. It ensures that:
                    
                    1. A nonce obtained from the /nonce endpoint is valid for a DPoP proof.
                    2. After the nonce is used in a successful DPoP proof (token request), it is invalidated.
                    3. Attempting to reuse the same nonce in a subsequent DPoP proof MUST fail.
                    4. This prevents replay attacks for batch issuance renewal.
                    
                    Vulnerability: A nonce that was used for DPoP was never invalidated and thus did not do 
                    any replay prevention. Replay attacks for batch issuance renewal could be easily done 
                    without any protection.
                    """
    )
    @Tag(ReportingTags.UCI_I2)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void dpopNonceInvalidationAfterUsage_preventReplayAttack() {
        CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialOffer("bound_example_sd_jwt");
        assertThat(offer).isNotNull();
        assertThat(offer.getOfferDeeplink()).isNotBlank();

        URI deeplink = wallet.getIssuerContext()
                .getContextualizedUri(toUri(offer.getOfferDeeplink()));

        WalletBatchEntry batchEntry = new WalletBatchEntry(wallet);
        batchEntry.receiveDeepLinkAndValidateIt(deeplink);
        batchEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(batchEntry));
        batchEntry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(batchEntry));
        batchEntry.setCredentialConfigurationSupported();

        log.info("Wallet requests nonce and creates token request with DPoP proof");
        String firstNonce = wallet.collectDPoPNonce(batchEntry);
        assertThat(firstNonce).isNotBlank();

        URI tokenUri = batchEntry.getIssuerTokenUri();
        String firstDpopProof = createDpopProofForToken(tokenUri.toString(), "POST", firstNonce);

        log.info("Issuer receives token request and validates nonce");
        OAuthToken firstToken = wallet.collectTokenWithDPoP(batchEntry, firstDpopProof);
        assertThat(firstToken).isNotNull();
        assertThat(firstToken.getAccessToken()).isNotBlank();
        log.info("Token issued successfully, nonce should now be invalidated");

        log.info("Attacker attempts to reuse same nonce for replay attack");
        String replayDpopProof = createDpopProofForToken(tokenUri.toString(), "POST", firstNonce);

        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
            wallet.collectTokenWithDPoP(batchEntry, replayDpopProof);
        });

        assertThat(errorCode(ex))
                .as("Issuer should reject replay attempt with 401 Unauthorized")
                .isEqualTo(401);
        assertThat(errorJson(ex))
                .containsEntry("error", "invalid_dpop_proof")
                .containsEntry("error_description", "Must use valid server provided nonce");
        log.info("Replay attack prevented - nonce invalidation working correctly");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-483",
            summary = "DPoP Nonce Invalidation: Refresh Token Flow",
            description = """
                    This test verifies that nonces are properly invalidated in the refresh token flow:
                    
                    1. Get initial nonce and token with pre-authorized code.
                    2. Get a second nonce for refresh token request.
                    3. Use the second nonce to refresh the token - must succeed.
                    4. Immediately attempt to reuse the second nonce for another refresh - must fail.
                    5. Get a new nonce and successfully refresh with it.
                    
                    This ensures that batch issuance renewal requests cannot be replayed.
                    """
    )
    @Tag(ReportingTags.UCI_I2)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void dpopNonceInvalidationInRefreshFlow_preventReplay() {
        CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialOffer("bound_example_sd_jwt");
        assertThat(offer).isNotNull();

        URI deeplink = wallet.getIssuerContext()
                .getContextualizedUri(toUri(offer.getOfferDeeplink()));

        WalletBatchEntry batchEntry = new WalletBatchEntry(wallet);
        batchEntry.receiveDeepLinkAndValidateIt(deeplink);
        batchEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(batchEntry));
        batchEntry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(batchEntry));
        batchEntry.setCredentialConfigurationSupported();

        log.info("Wallet obtains initial token with refresh_token capability");
        String initialNonce = wallet.collectDPoPNonce(batchEntry);
        URI tokenUri = batchEntry.getIssuerTokenUri();
        String initialDpopProof = createDpopProofForToken(tokenUri.toString(), "POST", initialNonce);
        OAuthToken initialToken = wallet.collectTokenWithDPoP(batchEntry, initialDpopProof);
        batchEntry.setToken(initialToken);

        assertThat(initialToken.getRefreshToken())
                .as("Initial token must contain a refresh token")
                .isNotBlank();

        log.info("Wallet requests nonce and refreshes token");
        String firstRefreshNonce = wallet.collectDPoPNonce(batchEntry);
        assertThat(firstRefreshNonce).isNotBlank();

        String firstRefreshDpopProof = createDpopProofForToken(tokenUri.toString(), "POST", firstRefreshNonce);
        OAuthToken firstRefreshedToken = wallet.refreshTokenWithDPoP(batchEntry, firstRefreshDpopProof);

        assertThat(firstRefreshedToken)
                .as("First refresh with valid nonce must succeed")
                .isNotNull();
        assertThat(firstRefreshedToken.getAccessToken())
                .as("Refreshed access token must be provided")
                .isNotBlank();
        log.info("Token refreshed, nonce invalidated");

        batchEntry.setToken(firstRefreshedToken);

        log.info("Attacker attempts to replay first refresh nonce");
        String replayFirstRefreshDpopProof = createDpopProofForToken(tokenUri.toString(), "POST", firstRefreshNonce);

        assertThrows(HttpClientErrorException.class, () -> {
            wallet.refreshTokenWithDPoP(batchEntry, replayFirstRefreshDpopProof);
        });
        log.info("Replay attempt blocked");

        log.info("Wallet requests fresh nonce for second refresh");
        String secondRefreshNonce = wallet.collectDPoPNonce(batchEntry);
        assertThat(secondRefreshNonce)
                .as("New nonce must be different from the previous one")
                .isNotEqualTo(firstRefreshNonce);

        log.info("Wallet refreshes token with new nonce");
        String secondRefreshDpopProof = createDpopProofForToken(tokenUri.toString(), "POST", secondRefreshNonce);
        OAuthToken secondRefreshedToken = wallet.refreshTokenWithDPoP(batchEntry, secondRefreshDpopProof);

        assertThat(secondRefreshedToken)
                .as("Second refresh with fresh nonce must succeed")
                .isNotNull();
        assertThat(secondRefreshedToken.getAccessToken())
                .as("Second refreshed access token must be different from first refreshed token")
                .isNotEqualTo(firstRefreshedToken.getAccessToken());
        log.info("Second refresh successful with new nonce");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-484",
            summary = "DPoP Nonce Invalidation: Multiple Credential Requests",
            description = """
                    This test verifies that nonces are properly invalidated when making multiple
                    credential requests:
                    
                    1. Get initial token with DPoP and nonce.
                    2. Get a nonce for first credential request - must succeed.
                    3. Request credentials with this nonce - must succeed.
                    4. Create a new credential offer for the second batch.
                    5. Get a new nonce and successfully request credentials again.
                    
                    This ensures that batch issuance cannot be exploited through nonce replay.
                    """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void dpopNonceInvalidationInCredentialRequests_preventReplay() {
        CredentialWithDeeplinkResponse offer1 =
                issuerManager.createCredentialOffer("bound_example_sd_jwt");

        URI deeplink1 = wallet.getIssuerContext()
                .getContextualizedUri(toUri(offer1.getOfferDeeplink()));

        WalletBatchEntry batchEntry = new WalletBatchEntry(wallet);
        batchEntry.receiveDeepLinkAndValidateIt(deeplink1);
        batchEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(batchEntry));
        batchEntry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(batchEntry));
        batchEntry.setCredentialConfigurationSupported();

        log.info("Wallet requests token for first batch issuance");
        String initialNonce = wallet.collectDPoPNonce(batchEntry);
        URI tokenUri = batchEntry.getIssuerTokenUri();
        String initialDpopProof = createDpopProofForToken(tokenUri.toString(), "POST", initialNonce);
        OAuthToken token = wallet.collectTokenWithDPoP(batchEntry, initialDpopProof);
        batchEntry.setToken(token);
        batchEntry.setCNonce(wallet.collectCNonce(batchEntry));

        log.info("Wallet requests first batch of credentials");
        batchEntry.generateHolderKeys();
        batchEntry.createProofs();

        var firstCredentials = wallet.getVerifiableCredentialFromIssuer(batchEntry);

        assertThat(firstCredentials)
                .as("First credential request must succeed and return a list of credentials")
                .isNotNull()
                .isNotEmpty();

        int actualBatchSize = firstCredentials.size();
        assertThat(actualBatchSize)
                .as("Batch should contain at least one credential")
                .isPositive();
        log.info("First batch issued with {} credentials", actualBatchSize);

        log.info("Wallet creates new credential offer for second batch");
        CredentialWithDeeplinkResponse offer2 =
                issuerManager.createCredentialOffer("bound_example_sd_jwt");

        URI deeplink2 = wallet.getIssuerContext()
                .getContextualizedUri(toUri(offer2.getOfferDeeplink()));

        WalletBatchEntry batchEntry2 = new WalletBatchEntry(wallet);
        batchEntry2.receiveDeepLinkAndValidateIt(deeplink2);
        batchEntry2.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(batchEntry2));
        batchEntry2.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(batchEntry2));
        batchEntry2.setCredentialConfigurationSupported();

        log.info("Wallet requests token for second batch with new nonce");
        String secondInitialNonce = wallet.collectDPoPNonce(batchEntry2);
        String secondInitialDpopProof = createDpopProofForToken(tokenUri.toString(), "POST", secondInitialNonce);
        OAuthToken secondToken = wallet.collectTokenWithDPoP(batchEntry2, secondInitialDpopProof);
        batchEntry2.setToken(secondToken);
        batchEntry2.setCNonce(wallet.collectCNonce(batchEntry2));

        log.info("Wallet requests second batch of credentials");
        batchEntry2.generateHolderKeys();
        batchEntry2.createProofs();

        var secondCredentials = wallet.getVerifiableCredentialFromIssuer(batchEntry2);

        assertThat(secondCredentials)
                .as("Second credential request with fresh nonce must succeed")
                .hasSize(actualBatchSize);

        assertThat(firstCredentials)
                .as("First and second credential batches should be different")
                .isNotEqualTo(secondCredentials);

        log.info("Second batch issued - nonces properly invalidated between requests");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-485",
            summary = "DPoP – Register Holder Public Key and reject token request when key changes",
            description = """
                    This test verifies that when a DPoP public key is registered for a pre-authorized code,
                    a subsequent token request using the same pre-authorized code but a different DPoP key
                    MUST be rejected by the issuer.
                    """
    )
    @Tag(ReportingTags.UCI_I2)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void dpopRegisterHolderKey_thenRejectDifferentKey() {
        CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialOffer("bound_example_sd_jwt");
        assertThat(offer).isNotNull();

        URI deeplink = wallet.getIssuerContext()
                .getContextualizedUri(toUri(offer.getOfferDeeplink()));

        WalletBatchEntry batchEntry = new WalletBatchEntry(wallet);
        batchEntry.receiveDeepLinkAndValidateIt(deeplink);
        batchEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(batchEntry));
        batchEntry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(batchEntry));
        batchEntry.setCredentialConfigurationSupported();

        // Obtain a nonce and request a token with the first DPoP key
        String nonce = wallet.collectDPoPNonce(batchEntry);
        assertThat(nonce).isNotBlank();
        URI tokenUri = batchEntry.getIssuerTokenUri();
        String firstDpopProof = createDpopProofForToken(tokenUri.toString(), "POST", nonce);

        OAuthToken firstToken = wallet.collectTokenWithDPoP(batchEntry, firstDpopProof);
        assertThat(firstToken).isNotNull();
        assertThat(firstToken.getAccessToken()).isNotBlank();
        assertThat(firstToken.getRefreshToken()).isNotBlank();

        // set token on batchEntry so we can use refresh flow
        batchEntry.setToken(firstToken);

        // Now create a new DPoP keypair and try to request a new access token using the refresh token but a different key
        KeyPair otherKeyPair = ECCryptoSupport.generateECKeyPair();
        ECKey otherPub = new ECKey.Builder(Curve.P_256, (java.security.interfaces.ECPublicKey) otherKeyPair.getPublic())
                .keyUse(KeyUse.SIGNATURE)
                .keyID("holder-dpop-key-other-" + UUID.randomUUID())
                .build();

        // get a nonce for the refresh flow
        String refreshNonce = wallet.collectDPoPNonce(batchEntry);
        assertThat(refreshNonce).isNotBlank();

        String secondDpopProofDifferentKey = createDpopProofForTokenWithKey(otherKeyPair, otherPub, tokenUri.toString(), "POST", refreshNonce);

        // The refresh token request using a different key should be rejected by the issuer
        assertThatThrownBy(() -> wallet.refreshTokenWithDPoP(batchEntry, secondDpopProofDifferentKey))
                .as("Refresh request using a different DPoP key MUST be rejected")
                .isInstanceOf(HttpClientErrorException.class)
                .hasMessageContaining("401");
    }

    private String createDpopProofForTokenWithKey(KeyPair keyPair, ECKey pubKey, String uri, String method, String nonce) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("dpop+jwt"))
                    .jwk(pubKey)
                    .build();

            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .claim("htm", method)
                    .claim("htu", uri)
                    .issueTime(new Date())
                    .jwtID(UUID.randomUUID().toString());

            if (nonce != null) {
                claimsBuilder.claim("nonce", nonce);
            }

            JWTClaimsSet claims = claimsBuilder.build();

            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(ECCryptoSupport.createECDSASigner(keyPair.getPrivate()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create DPoP proof for token request with custom key", e);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-486",
            summary = "MITM Attack Prevention: DPoP URI Binding Prevents Credential Request Hijacking",
            description = """
                    This test verifies that a Man-in-the-Middle (MITM) attacker cannot hijack a credential request.
                    
                    Scenario:
                    Hold (Holder/Wallet) -> Iss (Issuer)
                    1. Holder gets token from issuer with valid DPoP proof.
                    2. Holder prepares credential request data.
                    3. Att (Attacker/MITM) intercepts the request.
                    4. Attacker creates a DPoP proof bound to attacker's URL (Hold -> Att).
                    5. Attacker forwards the request to the issuer but with the DPoP proof bound to attacker-url.
                       So the request arrives at issuer's /credential endpoint, but DPoP htu=attacker-url/credential.
                    6. Issuer validates DPoP and finds htu != actual request URI.
                    7. Issuer MUST reject with 401 Unauthorized.
                    
                    This verifies RFC 9449: DPoP URI binding prevents MITM reuse of tokens on different endpoints.
                    """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void dpopMitmAttackPrevention_rejectUriTampering() throws JsonProcessingException {
        CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialOffer("bound_example_sd_jwt");
        assertThat(offer).isNotNull();

        URI deeplink = wallet.getIssuerContext()
                .getContextualizedUri(toUri(offer.getOfferDeeplink()));

        WalletBatchEntry batchEntry = new WalletBatchEntry(wallet);
        batchEntry.receiveDeepLinkAndValidateIt(deeplink);
        batchEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(batchEntry));
        batchEntry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(batchEntry));
        batchEntry.setCredentialConfigurationSupported();

        log.info("Wallet requests token from issuer with DPoP proof");
        String tokenNonce = wallet.collectDPoPNonce(batchEntry);
        URI tokenUri = batchEntry.getIssuerTokenUri();
        String dpopProofForToken = createDpopProofForToken(tokenUri.toString(), "POST", tokenNonce);

        OAuthToken token = wallet.collectTokenWithDPoP(batchEntry, dpopProofForToken);
        assertThat(token).isNotNull();
        assertThat(token.getAccessToken()).isNotBlank();

        batchEntry.setToken(token);

        log.info("Wallet prepares credential request with 3 holder keys");
        batchEntry.generateHolderKeys();
        batchEntry.createProofs();

        URI realCredentialUri = batchEntry.getIssuerCredentialUri();
        assertThat(realCredentialUri).isNotNull();

        log.info("Attacker intercepts request and creates DPoP proof bound to attacker-url");
        URI attackerCredentialUri = URI.create("http://attacker-url:8080/oid4vci/api/credential");
        String credentialNonce = wallet.collectDPoPNonce(batchEntry);
        String attackerDpopProof = createDpopProofForCredentialRequest(attackerCredentialUri, credentialNonce);

        log.info("Attacker forwards request to real issuer with attacker's DPoP proof");
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () -> {
            wallet.postCredentialRequestWithCustomDPoP(batchEntry, attackerDpopProof, realCredentialUri);
        });

        log.info("Issuer rejects request due to htu mismatch");
        assertThat(errorCode(ex))
                .as("Issuer should reject with 401 Unauthorized")
                .isEqualTo(401);
        assertThat(errorJson(ex))
                .containsEntry("error", "invalid_dpop_proof")
                .containsEntry("error_description", "URL mismatch between DPoP and request");
        log.info("MITM attack prevented - DPoP URI binding working correctly");
    }

    private String createDpopProofForCredentialRequest(URI uri, String nonce) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("dpop+jwt"))
                    .jwk(wallet.getDpopPublicKey())
                    .build();

            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .claim("htm", "POST")
                    .claim("htu", uri.toString())
                    .issueTime(new Date())
                    .jwtID(UUID.randomUUID().toString());

            if (nonce != null) {
                claimsBuilder.claim("nonce", nonce);
            }

            JWTClaimsSet claims = claimsBuilder.build();

            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(ECCryptoSupport.createECDSASigner(wallet.getDpopKeyPair().getPrivate()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create DPoP proof for credential request", e);
        }
    }

    private String createDpopProofForToken(String uri, String method, String nonce) {
        return createDpopProofForToken(uri, method, nonce, null);
    }

    private String createDpopProofForToken(String uri, String method, String nonce, String audience) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("dpop+jwt"))
                    .jwk(wallet.getDpopPublicKey())
                    .build();

            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .audience(audience)
                    .claim("htm", method)
                    .claim("htu", uri)
                    .issueTime(new Date())
                    .jwtID(UUID.randomUUID().toString());

            if (nonce != null) {
                claimsBuilder.claim("nonce", nonce);
            }

            JWTClaimsSet claims = claimsBuilder.build();

            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(ECCryptoSupport.createECDSASigner(wallet.getDpopKeyPair().getPrivate()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create DPoP proof for token request", e);
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-480",
            summary = "Vulnerability Check: Holder Binding Proof Replay Protection",
            description = """
                    Vulnerability: The nonce validation was missing a UUID check for self-contained nonces,
                    allowing attackers to replay holder binding proofs observed over the network.
                    The validateNonce function only checked expiry but not the nonce UUID value itself.
                    
                    Test scenario:
                    1. Wallet creates credential request with batch of holder binding proofs, each with unique nonce.
                    2. Issuer receives request, validates proofs (including nonces), and registers nonces as used.
                    3. Issuer issues credentials.
                    4. Attacker captures and replays the exact same holder binding proofs (same JWT strings with same nonces).
                    5. Issuer must reject the replayed proofs because:
                       - Each nonce UUID has been registered as already used
                       - Self-contained nonces must be tracked to prevent replays
                    6. Wallet requests new credential batch with new nonces - must succeed.
                    """
    )
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void holderBindingReplayProtection_preventProofReuse() {
        final CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialOffer("bound_example_sd_jwt");
        assertThat(offer).isNotNull();

        final URI deeplink = wallet.getIssuerContext()
                .getContextualizedUri(toUri(offer.getOfferDeeplink()));

        final WalletBatchEntry batchEntry = new WalletBatchEntry(wallet);
        batchEntry.receiveDeepLinkAndValidateIt(deeplink);
        batchEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(batchEntry));
        batchEntry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(batchEntry));
        batchEntry.setCredentialConfigurationSupported();

        log.info("Wallet requests token for first credential batch");
        final String tokenNonce = wallet.collectDPoPNonce(batchEntry);
        final URI tokenUri = batchEntry.getIssuerTokenUri();
        final String tokenDpopProof = createDpopProofForToken(tokenUri.toString(), "POST", tokenNonce);
        final OAuthToken token = wallet.collectTokenWithDPoP(batchEntry, tokenDpopProof);
        assertThat(token).isNotNull();
        batchEntry.setToken(token);
        batchEntry.setCNonce(wallet.collectCNonce(batchEntry));

        log.info("Wallet generates holder keys and creates holder binding proofs with unique nonces");
        final int batchSize = batchEntry.getIssuerMetadata().getBatchCredentialIssuance().getBatchSize();
        batchEntry.generateHolderKeys();
        batchEntry.createProofs();

        log.info("Capturing initial holder binding proof JWT strings (containing nonces)");
        final List<JwtProof> initialProofJwts = batchEntry.getProofs();
        assertThat(initialProofJwts)
                .as("Initial proofs should be generated for batch size")
                .hasSize(batchSize);

        log.info("Wallet sends credential request with batch of {} holder binding proofs", batchSize);
        final List<String> firstCredentials = wallet.getVerifiableCredentialFromIssuer(batchEntry);
        assertThat(firstCredentials)
                .as("First credential batch must succeed")
                .hasSize(batchSize);

        log.info("Creating new credential offer for attacker's replay attempt");
        final CredentialWithDeeplinkResponse offer2 =
                issuerManager.createCredentialOffer("bound_example_sd_jwt");

        final URI deeplink2 = wallet.getIssuerContext()
                .getContextualizedUri(toUri(offer2.getOfferDeeplink()));

        final WalletBatchEntry batchEntry2 = new WalletBatchEntry(wallet);
        batchEntry2.receiveDeepLinkAndValidateIt(deeplink2);
        batchEntry2.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(batchEntry2));
        batchEntry2.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(batchEntry2));
        batchEntry2.setCredentialConfigurationSupported();

        log.info("Attacker obtains legitimate token with new pre-authorized code");
        final String attackerTokenNonce = wallet.collectDPoPNonce(batchEntry2);
        final String attackerTokenProof = createDpopProofForToken(tokenUri.toString(), "POST", attackerTokenNonce);
        final OAuthToken attackerToken = wallet.collectTokenWithDPoP(batchEntry2, attackerTokenProof);
        batchEntry2.setToken(attackerToken);

        log.info("Attacker replays captured holder binding proof JWTs");
        batchEntry2.generateHolderKeys();
        batchEntry2.setProofsFromJwt(initialProofJwts);

        assertThat(batchEntry2.getProofs())
                .as("Attacker's proofs are exact copies as first batch")
                .isEqualTo(initialProofJwts);

        log.info("Attacker sends credential request with replayed holder binding proof JWTs");
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class, () ->
                wallet.getVerifiableCredentialFromIssuer(batchEntry2)
        );

        assertThat(errorCode(ex))
                .as("Issuer must reject credential request with replayed nonces")
                .isEqualTo(422);
        assertThat(errorJson(ex))
                .as("Error should indicate proof validation failure due to nonce replay")
                .containsEntry("error_description", "Unprocessable Entity")
                .containsEntry("detail", "proofs.jwt: must not be empty");
    }
}


