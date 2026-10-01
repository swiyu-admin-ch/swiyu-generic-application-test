package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto;

import ch.admin.bj.swiyu.dpop.DpopConstants;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.dpop.DpopHashUtil;
import ch.admin.bj.swiyu.dpop.DpopJwtValidator;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Characterizes the DPoP proofs the Wallet sends ({@link DPoPSupport}).
 *
 * <p>Specification: RFC 9449 §4.2 (`typ` `dpop+jwt`, `jwk`, `jti`, `htm`, `htu`, `iat`, `ath`, `nonce`), Swiss
 * issuance profile §3.5, §8.2 and §9 (a DPoP header on token, credential, and deferred requests), Swiss profiles (ES256).
 * The expected values are written from the specification; the library's {@link DpopJwtValidator} is only a reference
 * for "a Credential Issuer accepts this".
 */
class DPoPSupportTest {

    private static final URI TOKEN_URI = URI.create("https://issuer.example.com/oid4vci/api/token");
    private static final String NONCE = "server-provided-dpop-nonce";
    private static final String ACCESS_TOKEN = "7e3d56f6-cfc0-4d33-98ad-7147a64f8296";

    private KeyPair keyPair;
    private ECKey publicJwk;

    @BeforeEach
    void setUp() {
        keyPair = ECCryptoSupport.generateECKeyPair();
        publicJwk = ECCryptoSupport.toPublicJwk(keyPair.getPublic(), "holder-dpop-key");
    }

    @Test
    void proof_whenCreatedForTheTokenEndpoint_thenHasTheHeaderAndClaimsOfRfc9449() throws Exception {
        final SignedJWT proof = SignedJWT.parse(DPoPSupport.createDpopProofForToken(
                TOKEN_URI.toString(), NONCE, keyPair, publicJwk));

        assertThat(proof.getHeader().getType().getType())
                .as("RFC 9449 §4.2: typ is dpop+jwt")
                .isEqualTo("dpop+jwt");
        assertThat(proof.getHeader().getAlgorithm().getName())
                .as("Swiss profiles: ES256")
                .isEqualTo("ES256");
        assertThat(proof.getHeader().getJWK().toECKey().toPublicJWK().getX())
                .as("RFC 9449 §4.2: the public key of the proof is in the jwk header")
                .isEqualTo(publicJwk.getX());
        assertThat(proof.getHeader().getJWK().isPrivate())
                .as("RFC 9449 §4.2: the jwk header MUST NOT contain a private key")
                .isFalse();

        final JWTClaimsSet claims = proof.getJWTClaimsSet();
        assertThat(claims.getStringClaim("htm"))
                .isEqualTo("POST");
        assertThat(claims.getStringClaim("htu"))
                .isEqualTo(TOKEN_URI.toString());
        assertThat(claims.getStringClaim("nonce"))
                .isEqualTo(NONCE);
        assertThat(claims.getJWTID())
                .isNotBlank();
        assertThat(claims.getIssueTime().toInstant())
                .isBetween(Instant.now().minusSeconds(60), Instant.now().plusSeconds(5));
        assertThat(claims.getClaims())
                .as("a proof without an access token carries no ath")
                .doesNotContainKey("ath");
        assertThat(proof.verify(new ECDSAVerifier(publicJwk)))
                .isTrue();
    }

    @Test
    void proof_whenBoundToAnAccessToken_thenAthIsTheSha256OfItsAsciiBytes() throws Exception {
        final SignedJWT proof = SignedJWT.parse(DPoPSupport.createDpopProofForToken(
                TOKEN_URI.toString(), NONCE, keyPair, publicJwk, ACCESS_TOKEN));

        final String expectedAth = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(ACCESS_TOKEN.getBytes(StandardCharsets.US_ASCII)));
        assertThat(proof.getJWTClaimsSet().getStringClaim("ath"))
                .as("RFC 9449 §4.2: ath is base64url(SHA-256(ASCII(access token)))")
                .isEqualTo(expectedAth)
                .as("the library helper the Credential Issuer uses computes the same value")
                .isEqualTo(DpopHashUtil.sha256(ACCESS_TOKEN));
    }

    @Test
    void proofs_whenCreatedTwice_thenHaveDistinctIdentifiers() throws Exception {
        final String first = SignedJWT.parse(DPoPSupport.createDpopProofForToken(
                TOKEN_URI.toString(), NONCE, keyPair, publicJwk)).getJWTClaimsSet().getJWTID();
        final String second = SignedJWT.parse(DPoPSupport.createDpopProofForToken(
                TOKEN_URI.toString(), NONCE, keyPair, publicJwk)).getJWTClaimsSet().getJWTID();

        assertThat(first)
                .as("RFC 9449 §4.2: jti is unique per proof so a replayed proof can be detected")
                .isNotEqualTo(second);
    }

    @Test
    void proof_whenCheckedByTheDpopValidatorsOfTheLibrary_thenIsAccepted() throws Exception {
        final SignedJWT proof = DpopJwtValidator.parse(DPoPSupport.createDpopProofForToken(
                TOKEN_URI.toString(), NONCE, keyPair, publicJwk, ACCESS_TOKEN));

        DpopJwtValidator.validateMandatoryClaims(proof.getHeader(), proof.getJWTClaimsSet());
        DpopJwtValidator.validateTyp(proof.getHeader());
        DpopJwtValidator.validateAlgorithm(proof.getHeader(), DpopConstants.SUPPORTED_ALGORITHMS);
        DpopJwtValidator.validatePublicKeyNotPrivate(proof.getHeader().getJWK());
        DpopJwtValidator.validateSignature(proof, proof.getHeader().getJWK());
        DpopJwtValidator.validateHtm("POST", proof.getJWTClaimsSet());
        DpopJwtValidator.validateHtu(TOKEN_URI, proof.getJWTClaimsSet().getStringClaim("htu"), TOKEN_URI);
        DpopJwtValidator.validateIssuedAt(proof.getJWTClaimsSet(), 60, Clock.systemUTC());
    }

    @Test
    void libraryReference_whenTheUrlDiffers_thenRejects() throws Exception {
        final SignedJWT proof = DpopJwtValidator.parse(DPoPSupport.createDpopProofForToken(
                TOKEN_URI.toString(), NONCE, keyPair, publicJwk));
        final URI other = URI.create("https://issuer.example.com/oid4vci/api/credential");

        assertThatThrownBy(() -> DpopJwtValidator.validateHtu(other, proof.getJWTClaimsSet().getStringClaim("htu"), other))
                .as("the reference must discriminate, otherwise the acceptance test above proves nothing")
                .isInstanceOf(RuntimeException.class);
    }
}
