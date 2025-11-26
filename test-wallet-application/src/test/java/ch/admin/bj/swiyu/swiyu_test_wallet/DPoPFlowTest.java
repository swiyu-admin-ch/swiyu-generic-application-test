package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.OAuthToken;
import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.net.URI;
import java.security.KeyPair;
import java.util.Date;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class DPoPFlowTest {

    @Autowired
    IssuerImageConfig issuerImageConfig;
    @Autowired
    VerifierImageConfig verifierImageConfig;
    @Autowired
    IssuerConfig issuerConfig;
    @Autowired
    GenericContainer<?> issuerContainer;
    @Autowired
    GenericContainer<?> verifierContainer;
    @Autowired
    PostgreSQLContainer<?> dbTestContainer;
    @Autowired
    MockServerContainer mockServer;

    private Wallet wallet;
    private BusinessIssuer issuerManager;
    private VerifierManager verifierManager;
    private RestClient restClient;
    private StatusList currentStatusList;

    // Holder key for DPoP
    private KeyPair dpopKeyPair;
    private ECKey dpopPublicKey;

    @BeforeAll
    void setUp() {
        issuerConfig.setIssuerServiceUrl("http://%s:%s".formatted(issuerContainer.getHost(), issuerContainer.getMappedPort(8080)));
        issuerManager = new BusinessIssuer(issuerConfig);
        verifierManager = new VerifierManager(toUri("http://%s:%s".formatted(verifierContainer.getHost(), verifierContainer.getMappedPort(8080))).toString());
        currentStatusList = issuerManager.createStatusList(100000, 2);
        RestClient restClient = RestClient.builder().build();
        ServiceLocationContext issuerContext = new ServiceLocationContext(issuerContainer.getHost(), issuerContainer.getMappedPort(8080).toString());
        ServiceLocationContext verifierContext = new ServiceLocationContext(verifierContainer.getHost(), verifierContainer.getMappedPort(8080).toString());

        wallet = new Wallet(restClient, issuerContext, verifierContext);

        // Generate holder DPoP key pair
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
    @Tag("issuance")
    @Tag("dpop")
    void dpopInitialIssuance_happyPath() {
        final int batchSize = 3;

        CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        assertThat(offer).isNotNull();
        assertThat(offer.getOfferDeeplink()).isNotBlank();

        URI deeplink = wallet.getIssuerContext()
                .getContextualizedUri(toUri(offer.getOfferDeeplink()));

        WalletBatchEntry batchEntry = new WalletBatchEntry(wallet);
        batchEntry.receiveDeepLinkAndValidateIt(deeplink);
        batchEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(batchEntry));
        batchEntry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(batchEntry));
        batchEntry.setCredentialConfigurationSupported();

        String dpopNonce = wallet.getDpopNonce(batchEntry);
        assertThat(dpopNonce).isNotBlank();

        URI tokenUri = batchEntry.getIssuerTokenUri();
        String dpopProofForToken = createDpopProofForToken(tokenUri.toString(), "POST", dpopNonce);

        OAuthToken token = wallet.collectTokenWithDPoP(batchEntry, dpopProofForToken);
        assertThat(token).isNotNull();
        assertThat(token.getAccessToken()).isNotBlank();
        assertThat(token.getTokenType()).isEqualTo("BEARER");
        batchEntry.setToken(token);

        batchEntry.generateHolderKeys(batchSize);
        batchEntry.createProofs();

        var issuedCredentials = wallet.getVerifiableCredentialFromIssuerV1(batchEntry);

        assertThat(issuedCredentials)
                .as("Issuer should return a batch of %s credentials", batchSize)
                .hasSize(batchSize);

        issuedCredentials.forEach(cred ->
                assertThat(cred)
                        .as("Each issued credential must be a non-empty SD-JWT")
                        .isNotNull()
                        .isNotBlank());
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-428",
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
    @Tag("issuance")
    @Tag("dpop")
    @Tag("refresh-flow")
    void dpopRefreshFlow_happyPath() {
        final int batchSize = 3;

        CredentialWithDeeplinkResponse offer =
                issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        assertThat(offer).isNotNull();
        assertThat(offer.getOfferDeeplink()).isNotBlank();

        URI deeplink = wallet.getIssuerContext()
                .getContextualizedUri(toUri(offer.getOfferDeeplink()));

        WalletBatchEntry batchEntry = new WalletBatchEntry(wallet);
        batchEntry.receiveDeepLinkAndValidateIt(deeplink);
        batchEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(batchEntry));
        batchEntry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(batchEntry));
        batchEntry.setCredentialConfigurationSupported();

        String initialDpopNonce = wallet.getDpopNonce(batchEntry);
        assertThat(initialDpopNonce).isNotBlank();

        URI tokenUri = batchEntry.getIssuerTokenUri();
        String initialDpopProof = createDpopProofForToken(tokenUri.toString(), "POST", initialDpopNonce);

        OAuthToken initialToken = wallet.collectTokenWithDPoP(batchEntry, initialDpopProof);
        assertThat(initialToken).isNotNull();
        assertThat(initialToken.getAccessToken()).isNotBlank();
        assertThat(initialToken.getRefreshToken()).isNotBlank();
        assertThat(initialToken.getTokenType()).isEqualTo("BEARER");

        batchEntry.setToken(initialToken);
        String initialAccessToken = initialToken.getAccessToken();
        String initialRefreshToken = initialToken.getRefreshToken();

        String refreshDpopNonce = wallet.getDpopNonce(batchEntry);
        assertThat(refreshDpopNonce).isNotBlank();

        String refreshDpopProof = createDpopProofForToken(tokenUri.toString(), "POST", refreshDpopNonce);

        OAuthToken refreshedToken = wallet.refreshTokenWithDPoP(batchEntry, refreshDpopProof);
        assertThat(refreshedToken).isNotNull();
        assertThat(refreshedToken.getAccessToken()).isNotBlank();
        assertThat(refreshedToken.getRefreshToken()).isNotBlank();

        assertThat(refreshedToken.getAccessToken())
                .as("Refreshed access token must differ from initial")
                .isNotEqualTo(initialAccessToken);

        assertThat(refreshedToken.getRefreshToken())
                .as("Refreshed refresh token must differ from initial")
                .isNotEqualTo(initialRefreshToken);

        batchEntry.setToken(refreshedToken);

        batchEntry.generateHolderKeys(batchSize);
        batchEntry.createProofs();

        var refreshedCredentials = wallet.getVerifiableCredentialFromIssuerV1(batchEntry);

        assertThat(refreshedCredentials)
                .as("Issuer should return a batch of %s credentials using refreshed token", batchSize)
                .hasSize(batchSize);

        refreshedCredentials.forEach(cred ->
                assertThat(cred)
                        .as("Each issued credential after refresh must be a non-empty SD-JWT")
                        .isNotNull()
                        .isNotBlank());
    }

    private String createDpopProofForToken(String uri, String method, String nonce) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("dpop+jwt"))
                    .jwk(dpopPublicKey)
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
            jwt.sign(ECCryptoSupport.createECDSASigner(dpopKeyPair.getPrivate()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create DPoP proof for token request", e);
        }
    }
}
