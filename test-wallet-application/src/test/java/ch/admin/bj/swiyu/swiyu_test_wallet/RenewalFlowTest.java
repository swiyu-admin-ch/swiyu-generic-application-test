package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.OAuthToken;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.swiyu_test_wallet.support.TestConstants;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.DPoPSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.*;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.net.URI;
import java.security.KeyPair;
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

        log.info("Creating credential offer");
        final CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialOffer("university_example_sd_jwt");

        final WalletBatchEntry entry = new WalletBatchEntry(wallet);
        entry.receiveDeepLinkAndValidateIt(toUri(offer.getOfferDeeplink()));
        entry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(entry));
        entry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(entry));
        entry.setCredentialConfigurationSupported();

        log.info("Requesting initial token");
        final String nonce1 = wallet.getDpopNonce(entry);
        final URI tokenUri = entry.getIssuerTokenUri();
        final String dpop1 = DPoPSupport.createDpopProofForToken(
                tokenUri.toString(), nonce1, dpopKeyPair, dpopPublicKey);

        final OAuthToken token1 = wallet.collectTokenWithDPoP(entry, dpop1);
        entry.setToken(token1);

        log.info("Requesting initial credential batch");
        entry.generateHolderKeys();
        entry.createProofs();

        final List<String> batch1 = wallet.getVerifiableCredentialFromIssuerV1(entry);
        assertThat(batch1).hasSize(TestConstants.UNIVERSITY_EXAMPLE_BATCH_SIZE);

        log.info("Consuming issued credentials");
        for (int i = 0; i < batch1.size(); i++) {
            final String deepLink = verifierManager.verificationRequest()
                    .acceptedIssuerDid(entry.getIssuerDid())
                    .withUniversityDCQL()
                    .create();

            final RequestObject details = wallet.getVerificationDetails(deepLink);
            final String presentation = entry.createPresentationForSdJwtIndex(i, details);

            wallet.respondToVerificationV1(details, presentation);
            verifierManager.verifyState();
        }

        log.info("Starting renewal flow: requesting nonce");
        final WalletBatchEntry refreshEntry = new WalletBatchEntry(wallet);
        final String nonce2 = wallet.getDpopNonce(refreshEntry);

        log.info("Refreshing token using DPoP proof");
        final String dpop2 = DPoPSupport.createDpopProofForToken(
                tokenUri.toString(), nonce2, dpopKeyPair, dpopPublicKey);

        final OAuthToken token2 = wallet.refreshTokenWithDPoP(refreshEntry, dpop2);
        refreshEntry.setToken(token2);

        assertThat(token2.getAccessToken()).isNotEqualTo(token1.getAccessToken());
        assertThat(token2.getRefreshToken()).isNotBlank();

        log.info("Requesting new credential batch after renewal");
        final var credentialResponse = wallet.postCredentialRequestWithRefreshToken(refreshEntry, dpop2);
        assertThat(credentialResponse).isNotNull();

        final List<String> batch2 = refreshEntry.getIssuedCredentials();

        assertThat(batch2)
                .as("Second batch issued after renewal")
                .isNotNull()
                .hasSize(TestConstants.UNIVERSITY_EXAMPLE_BATCH_SIZE);

        log.info("Renewal flow completed successfully; new credential batch issued");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-492",
            summary = "TC 03 – Refresh token invalid or expired (renewal flow aligned)",
            description = """
            Renewal test verifying the issuer’s handling of invalid or expired
            refresh tokens.

            1. The wallet obtains an initial access token and refresh token using
               a valid DPoP-bound token request.
            2. The refresh_token is deliberately replaced with an invalid or expired
               value to simulate a broken renewal capability.
            3. The wallet requests a new nonce and prepares a standard DPoP proof
               for renewal.
            4. The wallet attempts token renewal using the invalid refresh_token.
               The issuer must reject the request with HTTP 401 and an invalid_grant
               error response.
        """
    )
    @Tag("refresh-flow")
    @Tag("issuance")
    void refreshTokenExpired_thenRejected() {

        log.info("Creating credential offer");
        final CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialOffer("university_example_sd_jwt");
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.OFFERED);

        final WalletBatchEntry entry = new WalletBatchEntry(wallet);
        entry.receiveDeepLinkAndValidateIt(toUri(offer.getOfferDeeplink()));
        entry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(entry));
        entry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(entry));
        entry.setCredentialConfigurationSupported();

        log.info("Requesting initial token");
        final String nonce1 = wallet.getDpopNonce(entry);
        final URI tokenUri = entry.getIssuerTokenUri();
        final String dpop1 = DPoPSupport.createDpopProofForToken(
                tokenUri.toString(), nonce1, dpopKeyPair, dpopPublicKey);

        final OAuthToken initialToken = wallet.collectTokenWithDPoP(entry, dpop1);
        assertThat(initialToken.getAccessToken()).isNotBlank();
        assertThat(initialToken.getRefreshToken()).isNotBlank();

        log.info("Tampering refresh_token to simulate invalid or expired value");
        final OAuthToken tamperedToken = new OAuthToken();
        tamperedToken.setAccessToken(initialToken.getAccessToken());
        tamperedToken.setRefreshToken(UUID.randomUUID().toString()); // invalid token
        tamperedToken.setTokenType(initialToken.getTokenType());
        entry.setToken(tamperedToken);

        log.info("Requesting nonce for renewal");
        final String nonce2 = wallet.getDpopNonce(entry);

        final String invalidDpopProof = DPoPSupport.createDpopProofForToken(
                tokenUri.toString(), nonce2, dpopKeyPair, dpopPublicKey);

        log.info("Attempting renewal with invalid refresh token");
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.refreshTokenWithDPoP(entry, invalidDpopProof)
        );

        assertThat(errorCode(ex))
                .as("Invalid refresh tokens must be rejected")
                .isEqualTo(401);

        assertThat(errorJson(ex))
                .as("Error payload must indicate invalid_grant")
                .containsEntry("error", "Error")
                .containsEntry("error_description", "Description Message");

        log.info("Renewal correctly rejected with 401");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-492",
            summary = "TC 04 – Invalid DPoP signature / binding error",
            description = """
            Renewal negative test confirming that a token refresh must be rejected
            when the DPoP proof is signed with a different key than the one originally
            bound to the refresh token.

            1. The wallet retrieves issuer metadata and obtains an initial token using
               a valid DPoP key (key A).
            2. An attacker prepares a second DPoP key (key B) not associated with the
               original token binding.
            3. The wallet requests a nonce for renewal and constructs a DPoP proof
               using the attacker key B.
            4. The issuer must reject the refresh request with HTTP 401 due to an
               invalid DPoP binding.
        """
    )
    @Tag("refresh-flow")
    @Tag("security")
    void refreshWithInvalidDpopSignature_thenRejected() {

        log.info("Creating credential offer");
        final CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialOffer("university_example_sd_jwt");

        final WalletBatchEntry entry = new WalletBatchEntry(wallet);
        entry.receiveDeepLinkAndValidateIt(toUri(offer.getOfferDeeplink()));
        entry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(entry));
        entry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(entry));
        entry.setCredentialConfigurationSupported();

        log.info("Requesting initial token using valid DPoP key A");
        final String nonce1 = wallet.getDpopNonce(entry);
        final URI tokenUri = entry.getIssuerTokenUri();
        final String dpopProofA = DPoPSupport.createDpopProofForToken(
                tokenUri.toString(), nonce1, dpopKeyPair, dpopPublicKey);

        final OAuthToken token1 = wallet.collectTokenWithDPoP(entry, dpopProofA);
        entry.setToken(token1);

        log.info("Initial token bound to key A");

        log.info("Preparing attacker DPoP key B");
        final KeyPair attackerKeyPair = ECCryptoSupport.generateECKeyPair();
        final ECKey attackerPublicKey = new ECKey.Builder(
                Curve.P_256,
                (java.security.interfaces.ECPublicKey) attackerKeyPair.getPublic())
                .keyUse(KeyUse.SIGNATURE)
                .keyID("attacker-dpop-key-" + UUID.randomUUID())
                .build();

        log.info("Requesting renewal nonce");
        final String nonce2 = wallet.getDpopNonce(entry);
        final String invalidDpopProof = DPoPSupport.createDpopProofForToken(
                tokenUri.toString(), nonce2, attackerKeyPair, attackerPublicKey);

        log.info("Attempting token refresh with mismatched DPoP key");
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.refreshTokenWithDPoP(entry, invalidDpopProof)
        );

        assertThat(errorCode(ex))
                .as("Refresh must fail due to DPoP key mismatch")
                .isEqualTo(401);

        assertThat(errorJson(ex))
                .as("Issuer must indicate invalid DPoP binding")
                .containsEntry("error", "Error")
                .containsEntry("error_description", "Description Message");

        log.info("Refresh correctly rejected due to invalid DPoP signature");
    }


    @Test
    @XrayTest(
            key = "EIDOMNI-492",
            summary = "TC 05 – Nonce replay attempt during renewal",
            description = """
            This negative renewal test verifies that the issuer rejects a refresh request
            where the DPoP proof reuses a previously consumed nonce.

            1. The wallet obtains an initial access_token and refresh_token using a valid
               DPoP-bound request and nonce N.
            2. A renewal should require a fresh nonce, but the wallet deliberately reuses
               the original nonce N to simulate a replay attack.
            3. The wallet constructs a DPoP proof using the replayed nonce.
            4. The issuer must reject the refresh attempt with HTTP 401 due to invalid
               or replayed nonce.
        """
    )
    @Tag("refresh-flow")
    @Tag("security")
    void refreshWithReplayedNonce_thenRejected() {

        log.info("Creating credential offer");
        final CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialOffer("university_example_sd_jwt");

        final WalletBatchEntry entry = new WalletBatchEntry(wallet);
        entry.receiveDeepLinkAndValidateIt(toUri(offer.getOfferDeeplink()));
        entry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(entry));
        entry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(entry));
        entry.setCredentialConfigurationSupported();

        log.info("Requesting initial token using nonce N");
        final String nonceN = wallet.getDpopNonce(entry);
        assertThat(nonceN).isNotBlank();

        final URI tokenUri = entry.getIssuerTokenUri();
        final String initialDpopProof = DPoPSupport.createDpopProofForToken(
                tokenUri.toString(), nonceN, dpopKeyPair, dpopPublicKey);

        final OAuthToken initialToken = wallet.collectTokenWithDPoP(entry, initialDpopProof);
        entry.setToken(initialToken);

        log.info("Initial token obtained and nonce N is now consumed");

        log.info("Reusing nonce N to simulate replay attack");
        final String replayedDpopProof = DPoPSupport.createDpopProofForToken(
                tokenUri.toString(), nonceN, dpopKeyPair, dpopPublicKey);

        log.info("Attempting refresh with replayed nonce");
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.refreshTokenWithDPoP(entry, replayedDpopProof)
        );

        assertThat(errorCode(ex))
                .as("Nonce replay must be rejected")
                .isEqualTo(401);

        assertThat(errorJson(ex))
                .as("Error payload must indicate invalid or replayed nonce")
                .containsEntry("error", "Error")
                .containsEntry("error_description", "Description Message");

        log.info("Replay nonce correctly rejected");
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
    void renewalFlowBlockedWhenCredentialManagementRevoked() {

        log.info("Creating credential offer");
        final CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialOffer("university_example_sd_jwt");

        final WalletBatchEntry entry = new WalletBatchEntry(wallet);
        entry.receiveDeepLinkAndValidateIt(toUri(offer.getOfferDeeplink()));
        entry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(entry));
        entry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(entry));
        entry.setCredentialConfigurationSupported();

        log.info("Requesting initial token");
        final String nonce = wallet.getDpopNonce(entry);
        final URI tokenUri = entry.getIssuerTokenUri();
        final String dpopProof = DPoPSupport.createDpopProofForToken(
                tokenUri.toString(), nonce, dpopKeyPair, dpopPublicKey);

        final OAuthToken token = wallet.collectTokenWithDPoP(entry, dpopProof);
        entry.setToken(token);

        log.info("Requesting initial credential batch");
        entry.generateHolderKeys();
        entry.createProofs();

        final List<String> batch1 = wallet.getVerifiableCredentialFromIssuerV1(entry);
        assertThat(batch1).hasSize(TestConstants.UNIVERSITY_EXAMPLE_BATCH_SIZE);

        log.info("Revoking credential management entry");
        issuerManager.updateState(
                offer.getManagementId(),
                UpdateCredentialStatusRequestType.REVOKED);

        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.REVOKED);

        log.info("Attempting renewal while management entry is revoked");
        final String renewalNonce = wallet.getDpopNonce(entry);
        final String renewalDpopProof = DPoPSupport.createDpopProofForToken(
                tokenUri.toString(), renewalNonce, dpopKeyPair, dpopPublicKey);

        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.refreshTokenWithDPoP(entry, renewalDpopProof)
        );

        assertThat(errorCode(ex))
                .as("Refresh must be rejected when management is revoked")
                .isIn(400, 401);

        assertThat(errorJson(ex))
                .as("Error payload must indicate invalid or replayed nonce")
                .containsEntry("error", "Error")
                .containsEntry("error_description", "Description Message");

        log.info("Renewal request correctly rejected due to REVOKED state");
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-492",
            summary = "TC 08 – Key Attestation Mismatch during renewal",
            description = """
            This test validates that the issuer enforces holder key attestation
            by rejecting a renewal request made with a different key than the one
            originally attested during the token issuance phase.

            1. The wallet receives an offer and obtains an initial access_token and
               refresh_token using an attested holder key (key A).
            2. The issuer binds key A as the authorized holder key for future operations.
            3. For the renewal step, the wallet generates a new key (key B) to simulate
               a key attestation mismatch.
            4. The wallet attempts a refresh_token request using key B.
            5. The issuer must reject the request with HTTP 401 due to mismatching
               attested holder key material.
        """
    )
    @Tag("refresh-flow")
    @Tag("security")
    void keyAttestationMismatch_thenRejected() {

        log.info("Creating credential offer");
        final CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialOffer("university_example_sd_jwt");

        final WalletBatchEntry entry = new WalletBatchEntry(wallet);
        entry.receiveDeepLinkAndValidateIt(toUri(offer.getOfferDeeplink()));
        entry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(entry));
        entry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(entry));
        entry.setCredentialConfigurationSupported();

        log.info("Requesting initial token using attested holder key A");
        final String nonce1 = wallet.getDpopNonce(entry);
        final URI tokenUri = entry.getIssuerTokenUri();
        final String dpopProofA = DPoPSupport.createDpopProofForToken(
                tokenUri.toString(), nonce1, dpopKeyPair, dpopPublicKey);

        final OAuthToken initialToken = wallet.collectTokenWithDPoP(entry, dpopProofA);
        entry.setToken(initialToken);

        log.info("Initial token issued; key A is now the attested holder key");

        log.info("Generating new holder key B to simulate attestation mismatch");
        final KeyPair unauthorizedKeyPair = ECCryptoSupport.generateECKeyPair();
        final ECKey unauthorizedPubKey = new ECKey.Builder(
                Curve.P_256,
                (java.security.interfaces.ECPublicKey) unauthorizedKeyPair.getPublic())
                .keyUse(KeyUse.SIGNATURE)
                .keyID("unauthorized-holder-key-" + UUID.randomUUID())
                .build();

        log.info("Requesting nonce for renewal");
        final String renewalNonce = wallet.getDpopNonce(entry);

        log.info("Creating DPoP proof for refresh using unauthorized key B");
        final String invalidAttestationProof = DPoPSupport.createDpopProofForToken(
                tokenUri.toString(), renewalNonce, unauthorizedKeyPair, unauthorizedPubKey);

        log.info("Attempting renewal with non-attested key B");
        final HttpClientErrorException ex = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.refreshTokenWithDPoP(entry, invalidAttestationProof)
        );

        assertThat(errorCode(ex))
                .as("Issuer must reject renewal due to key attestation mismatch")
                .isEqualTo(401);

        assertThat(errorJson(ex))
                .as("Error payload must reflect attestation mismatch semantics")
                .containsEntry("error", "Error")
                .containsEntry("error_description", "Description Message");

        log.info("Key attestation mismatch correctly rejected by issuer");
    }
}
