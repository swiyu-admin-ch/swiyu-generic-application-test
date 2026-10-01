package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Characterizes the Presentation the Wallet builds for a Verifier that asks for the whole credential
 * ({@link WalletBatchEntry#createPresentationForSdJwtIndex}): the Issuer-signed JWT, every Disclosure, and a Key
 * Binding JWT.
 *
 * <p>Specification: RFC 9901 §4.3 and §4.3.1 (Key Binding JWT), OID4VP 1.0 Appendix B.3.6 and §14.8 (`nonce` and
 * `aud`), Swiss VC profile 4.3 (`aud` is the `client_id` of the JWT-secured Authorization Request).
 */
class PresentationKeyBindingTest {

    private static final String CLIENT_ID = "decentralized_identifier:did:tdw:example:verifier";
    private static final String NONCE = "n-0S6_WzA2Mj";

    private WalletBatchEntry entry;
    private TestSdJwtVc credential;
    private ECKey holderPublicKey;
    private RequestObject requestObject;

    @BeforeEach
    void setUp() {
        final Wallet wallet = new Wallet(RestClient.create(), null, null);
        entry = new WalletBatchEntry(wallet);
        entry.generateHolderKeys(1);
        holderPublicKey = entry.getHolderPublicKeys().getFirst();
        credential = TestSdJwtVc.issueFor(holderPublicKey);
        entry.addIssuedCredential(credential.serialized());
        requestObject = new RequestObject().clientId(CLIENT_ID).nonce(NONCE);
    }

    @Test
    void presentation_whenWholeCredentialRequested_thenIsTheCredentialFollowedByAKeyBindingJwt() throws Exception {
        final String presentation = entry.createPresentationForSdJwtIndex(0, requestObject);

        assertThat(presentation)
                .startsWith(credential.serialized());
        final String keyBindingJwt = presentation.substring(credential.serialized().length());
        assertThat(keyBindingJwt)
                .doesNotContain("~")
                .matches("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");
    }

    @Test
    void keyBindingJwt_whenCreated_thenHasTheClaimsAndHeaderRequiredByRfc9901() throws Exception {
        final String presentation = entry.createPresentationForSdJwtIndex(0, requestObject);
        final SignedJWT keyBindingJwt = SignedJWT.parse(presentation.substring(credential.serialized().length()));

        assertThat(keyBindingJwt.getHeader().getType().getType())
                .as("RFC 9901 §4.3: typ MUST be kb+jwt")
                .isEqualTo("kb+jwt");
        assertThat(keyBindingJwt.getHeader().getAlgorithm().getName())
                .as("Swiss VC profile: ES256")
                .isEqualTo("ES256");
        assertThat(keyBindingJwt.getJWTClaimsSet().getClaims().keySet())
                .as("RFC 9901 §4.3: iat, aud, nonce, and sd_hash are required, and nothing else is added")
                .isEqualTo(Set.of("iat", "aud", "nonce", "sd_hash"));
        assertThat(keyBindingJwt.getJWTClaimsSet().getAudience())
                .as("OID4VP B.3.6 and §14.8: aud is the full Client Identifier, prefix included")
                .containsExactly(CLIENT_ID);
        assertThat(keyBindingJwt.getJWTClaimsSet().getStringClaim("nonce"))
                .as("OID4VP B.3.6: nonce is the nonce of the Authorization Request")
                .isEqualTo(NONCE);
        assertThat(keyBindingJwt.getJWTClaimsSet().getIssueTime().toInstant())
                .isBetween(Instant.now().minusSeconds(60), Instant.now().plusSeconds(5));
    }

    @Test
    void keyBindingJwt_whenCreated_thenSdHashCoversTheUsAsciiBytesUpToTheLastTilde() throws Exception {
        final String presentation = entry.createPresentationForSdJwtIndex(0, requestObject);
        final SignedJWT keyBindingJwt = SignedJWT.parse(presentation.substring(credential.serialized().length()));

        assertThat(keyBindingJwt.getJWTClaimsSet().getStringClaim("sd_hash"))
                .as("RFC 9901 §4.3.1: base64url(SHA-256(US-ASCII(<JWT>~<D1>~...~<DN>~)))")
                .isEqualTo(TestSdJwtVc.sha256Base64Url(credential.serialized()));
    }

    @Test
    void keyBindingJwt_whenCreated_thenIsSignedWithTheHolderKeyBoundInTheCredential() throws Exception {
        final String presentation = entry.createPresentationForSdJwtIndex(0, requestObject);
        final SignedJWT keyBindingJwt = SignedJWT.parse(presentation.substring(credential.serialized().length()));

        assertThat(keyBindingJwt.verify(new ECDSAVerifier(holderPublicKey)))
                .isTrue();
    }

    @Test
    void presentation_whenCheckedByTheVerifierValidatorsOfTheLibrary_thenIsAccepted() throws Exception {
        final String presentation = entry.createPresentationForSdJwtIndex(0, requestObject);

        final Map<String, Object> claims = SdJwtLibReference.verifyAndResolveClaims(
                presentation, credential.issuerPublicKey(), CLIENT_ID, NONCE);

        assertThat(claims)
                .containsKeys("name", "annual_salary", "address", "nationalities");
    }

    @Test
    void libraryReference_whenAudienceOrNonceDiffer_thenRejects() throws Exception {
        final String presentation = entry.createPresentationForSdJwtIndex(0, requestObject);

        assertThatThrownBy(() -> SdJwtLibReference.verifyAndResolveClaims(
                presentation, credential.issuerPublicKey(), "decentralized_identifier:did:tdw:example:other", NONCE))
                .as("the reference must discriminate, otherwise the acceptance test above proves nothing")
                .isInstanceOf(Exception.class);
        assertThatThrownBy(() -> SdJwtLibReference.verifyAndResolveClaims(
                presentation, credential.issuerPublicKey(), CLIENT_ID, "another-nonce"))
                .isInstanceOf(Exception.class);
    }
}
