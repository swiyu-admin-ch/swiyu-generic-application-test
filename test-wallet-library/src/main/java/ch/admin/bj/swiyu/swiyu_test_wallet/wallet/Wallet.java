package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.gen.issuer.model.IssuerMetadata;
import ch.admin.bj.swiyu.gen.issuer.model.NonceResponse;
import ch.admin.bj.swiyu.gen.issuer.model.OAuthAuthorizationServerMetadata;
import ch.admin.bj.swiyu.gen.issuer.model.OAuthToken;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlQueryDto;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockAttestationAuthority;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.TrustConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerHandle;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierHandle;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_response.CredentialResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequestObject;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.security.KeyPair;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * The fake Wallet of the Holder: it follows the specification as its {@link WalletProfile} says and can be made to deviate
 * on purpose through the artefact builders in {@code wallet.artefact}.
 *
 * <p>It holds the Wallet's settings and key material. What it says to a Credential Issuer (OID4VCI) is done by
 * {@link CredentialIssuerClient}, what it says to a Verifier (OID4VP) by {@link VerifierClient}; the methods below are the
 * journeys the tests call and delegate to them. The credentials it receives are in the {@link WalletBatchEntry} each
 * collection returns ({@link WalletBatchEntry#heldCredentials()}).
 */
@Getter
@Setter
public class Wallet {

    public static final String BEARER_PREFIX = "Bearer ";
    public static final String APPLICATION_JWT = "application/jwt";
    public static final String GRANT_TYPE = "grant_type";
    public static final String CREDENTIAL = "credential";
    public static final String CREDENTIALS = "credentials";
    public static final String TRANSACTION_ID = "transaction_id";
    public static final String SWIYU_API_VERSION_HEADER = "SWIYU-API-Version";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String VP_TOKEN = "vp_token";
    public static final String STATE = "state";
    public static final String DPOP = "DPoP";
    public static final String TRANSACTION_CODE = "tx_code";

    private final RestClient restClient;
    private ServiceLocationContext issuerContext;
    private ServiceLocationContext verifierContext;

    private WalletProfile profile = WalletProfile.unprotected();
    @Getter(AccessLevel.NONE)
    private final CredentialIssuerClient credentialIssuer = new CredentialIssuerClient(this);
    @Getter(AccessLevel.NONE)
    private final VerifierClient verifier = new VerifierClient(this);
    private KeyPair dpopKeyPair;
    private ECKey dpopPublicKey;
    private MockAttestationAuthority mockAttestationAuthority;
    private TrustConfig trustConfig;

    public Wallet(RestClient restClient, ServiceLocationContext issuerContext, ServiceLocationContext verifierContext) {
        this.restClient = restClient;
        this.issuerContext = issuerContext;
        this.verifierContext = verifierContext;
        initializeDPoPKey();
    }

    public Wallet(RestClient restClient, ServiceLocationContext issuerContext, ServiceLocationContext verifierContext, boolean useEncryption) {
        this(restClient, issuerContext, verifierContext);
        this.profile = profile.withEncryption(useEncryption);
    }

    public boolean isUseEncryption() {
        return profile.encryption();
    }

    public void setUseEncryption(final boolean useEncryption) {
        profile = profile.withEncryption(useEncryption);
    }

    public boolean isUseDPoP() {
        return profile.dpop();
    }

    public void setUseDPoP(final boolean useDPoP) {
        profile = profile.withDpop(useDPoP);
    }

    public boolean isSignedMetadataPreferred() {
        return profile.signedMetadataPreferred();
    }

    public void setSignedMetadataPreferred(final boolean signedMetadataPreferred) {
        profile = profile.withSignedMetadataPreferred(signedMetadataPreferred);
    }

    public String getCredentialRequestEncryptionEnc() {
        return profile.credentialRequestEncryptionEnc();
    }

    public void setCredentialRequestEncryptionEnc(final String enc) {
        profile = profile.withCredentialRequestEncryptionEnc(enc);
    }

    public String getCredentialResponseEncryptionEnc() {
        return profile.credentialResponseEncryptionEnc();
    }

    public void setCredentialResponseEncryptionEnc(final String enc) {
        profile = profile.withCredentialResponseEncryptionEnc(enc);
    }

    public Wallet useIssuer(final IssuerHandle issuer) {
        return useIssuer(issuer.serviceLocation());
    }

    public Wallet useIssuer(final ServiceLocationContext issuerContext) {
        this.issuerContext = issuerContext;
        return this;
    }

    public Wallet useVerifier(final VerifierHandle verifier) {
        return useVerifier(verifier.serviceLocation());
    }

    public Wallet useVerifier(final ServiceLocationContext verifierContext) {
        this.verifierContext = verifierContext;
        return this;
    }

    public Wallet useComponents(final IssuerHandle issuer, final VerifierHandle verifier) {
        return useIssuer(issuer).useVerifier(verifier);
    }

    public WalletBatchEntry createWalletBatchEntry() {
        return new WalletBatchEntry(this);
    }
    private void initializeDPoPKey() {
        dpopKeyPair = ECCryptoSupport.generateECKeyPair();
        dpopPublicKey = new ECKey.Builder(
                Curve.P_256,
                (java.security.interfaces.ECPublicKey) dpopKeyPair.getPublic())
                .keyUse(KeyUse.SIGNATURE)
                .keyID("holder-dpop-key-" + UUID.randomUUID())
                .build();
    }

    public String getIssuerTokenUri(WalletEntry walletEntry) {
        return walletEntry.getIssuerTokenUri().toString();
    }

    public String getIssuerCredentialUri(WalletEntry walletEntry) {
        return walletEntry.getIssuerCredentialUri().toString();
    }

    // ---- Protocol journeys: the OID4VCI and OID4VP clients do the work ----

    public WalletBatchEntry collectTransactionIdFromDeferredOffer(final URI issuerDeepLink) {
        return credentialIssuer.collectTransactionIdFromDeferredOffer(issuerDeepLink);
    }

    public WalletBatchEntry collectTransactionIdFromDeferredOffer(final WalletBatchEntry walletBatchEntry, final URI issuerDeepLink) {
        return credentialIssuer.collectTransactionIdFromDeferredOffer(walletBatchEntry, issuerDeepLink);
    }

    public OAuthAuthorizationServerMetadata getIssuerWellKnownConfiguration(WalletEntry walletEntry) {
        return credentialIssuer.getIssuerWellKnownConfiguration(walletEntry);
    }

    public IssuerMetadata getIssuerWellKnownMetadata(WalletEntry walletEntry) {
        return credentialIssuer.getIssuerWellKnownMetadata(walletEntry);
    }

    public OAuthToken collectToken(WalletEntry walletEntry) {
        return credentialIssuer.collectToken(walletEntry);
    }

    public ResponseEntity<NonceResponse> collectNonce(WalletEntry walletEntry) {
        return credentialIssuer.collectNonce(walletEntry);
    }

    public String collectCNonce(WalletEntry walletEntry) {
        return credentialIssuer.collectCNonce(walletEntry);
    }

    public List<String> getVerifiableCredentialFromIssuer(final WalletBatchEntry batchEntry) {
        return credentialIssuer.getVerifiableCredentialFromIssuer(batchEntry);
    }

    public CredentialResponse getCredentialFromTransactionId(WalletBatchEntry walletBatchEntry) {
        return credentialIssuer.getCredentialFromTransactionId(walletBatchEntry);
    }

    public CredentialResponse renewedCredentials(WalletBatchEntry batchEntry) {
        return credentialIssuer.renewedCredentials(batchEntry);
    }

    public WalletBatchEntry collectOffer(final URI offerDeepLink) {
        return credentialIssuer.collectOffer(offerDeepLink);
    }

    public WalletBatchEntry collectOffer(final URI offerDeepLink, final Integer count) {
        return credentialIssuer.collectOffer(offerDeepLink, count);
    }

    public WalletBatchEntry collectOffer(final WalletBatchEntry entry, final URI offerDeepLink) {
        return credentialIssuer.collectOffer(entry, offerDeepLink);
    }

    public WalletBatchEntry collectOffer(final WalletBatchEntry entry, final URI offerDeepLink, final Integer count) {
        return credentialIssuer.collectOffer(entry, offerDeepLink, count);
    }

    public CredentialResponse postCredentialRequest(final WalletBatchEntry walletEntry, final String dpopProofOverride) {
        return credentialIssuer.postCredentialRequest(walletEntry, dpopProofOverride);
    }

    public CredentialResponse postCredentialRequest(final WalletBatchEntry walletEntry) {
        return credentialIssuer.postCredentialRequest(walletEntry);
    }

    String resolveCredentialResponseEncryptionEnc(final List<String> supportedEncValues) {
        return credentialIssuer.resolveCredentialResponseEncryptionEnc(supportedEncValues);
    }

    public String collectDPoPNonce(WalletEntry walletEntry) {
        return credentialIssuer.collectDPoPNonce(walletEntry);
    }

    public OAuthToken collectTokenWithDPoP(WalletEntry walletEntry, String doPProof) {
        return credentialIssuer.collectTokenWithDPoP(walletEntry, doPProof);
    }

    public OAuthToken collectRefreshTokenWithDPoP(WalletEntry walletEntry, String doPProof) {
        return credentialIssuer.collectRefreshTokenWithDPoP(walletEntry, doPProof);
    }

    public OAuthToken refreshTokenWithDPoP(WalletEntry walletEntry, String doPProof) {
        return credentialIssuer.refreshTokenWithDPoP(walletEntry, doPProof);
    }

    public void postCredentialRequestWithCustomDPoP(WalletBatchEntry batchEntry, String customDpopProof, URI credentialUri) {
        credentialIssuer.postCredentialRequestWithCustomDPoP(batchEntry, customDpopProof, credentialUri);
    }

    public String generateDpopForCredentialEndpoint(final WalletEntry walletEntry) {
        return credentialIssuer.generateDpopForCredentialEndpoint(walletEntry);
    }

    public VerificationRequestObject getVerificationDetails(String verificationDeeplink) {
        return verifier.getVerificationDetails(verificationDeeplink);
    }

    public RequestObject getVerificationRequestObject(String verificationDeeplink) {
        return verifier.getVerificationRequestObject(verificationDeeplink);
    }

    public String getVerificationDetailSigned(String verificationDeeplink) {
        return verifier.getVerificationDetailSigned(verificationDeeplink);
    }

    public Optional<URI> respondToVerification(RequestObject requestObject, String token) {
        return verifier.respondToVerification(requestObject, token);
    }

    public ResponseEntity<String> respondToVerificationWithVpTokens( final RequestObject requestObject, final List<String> tokens ) {
        return verifier.respondToVerificationWithVpTokens(requestObject, tokens);
    }

    DcqlQueryDto resolveVerificationQuery(final RequestObject requestObject) {
        return verifier.resolveVerificationQuery(requestObject);
    }

    public Optional<URI> respondToVerificationWithError( final RequestObject requestObject, final String error, final String errorDescription ) {
        return verifier.respondToVerificationWithError(requestObject, error, errorDescription);
    }

    public Optional<URI> respondToVerificationWithError( final URI responseUri, final String state, final String error, final String errorDescription ) {
        return verifier.respondToVerificationWithError(responseUri, state, error, errorDescription);
    }
}
