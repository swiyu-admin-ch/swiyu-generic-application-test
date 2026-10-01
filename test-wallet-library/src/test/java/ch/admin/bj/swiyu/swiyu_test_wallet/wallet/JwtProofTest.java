package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockAttestationAuthority;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.KeyPair;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Characterizes the `jwt` key proof the Wallet puts in the `proofs` of a Credential Request ({@link JwtProof}).
 *
 * <p>Specification: OID4VCI 1.0 §8.2 and Appendix F.1 (`typ` `openid4vci-proof+jwt`, `jwk` or `kid` but not both, `aud` is
 * the Credential Issuer Identifier, `iat`, `nonce` is the `c_nonce`, no `iss` for an anonymous Pre-Authorized Code
 * Flow), Appendix D.1 (key attestation: `typ` `key-attestation+jwt`, `attested_keys`, `exp` required with the `jwt`
 * proof type).
 *
 * <p>Known simulation limit: Appendix F.1 says the `nonce` of the key attestation MUST be a server-provided `c_nonce`
 * when the Credential Issuer provided one. The attestation this wallet attaches carries no `nonce`.
 */
class JwtProofTest {

    private static final String CREDENTIAL_ISSUER = "https://issuer.example.com/oid4vci";
    private static final String C_NONCE = "tZignsnFbp";

    private KeyPair keyPair;
    private ECKey publicJwk;

    @BeforeEach
    void setUp() {
        keyPair = ECCryptoSupport.generateECKeyPair();
        publicJwk = ECCryptoSupport.toPublicJwk(keyPair.getPublic(), "key-a");
    }

    private JwtProof.JwtProofBuilder proof() {
        return JwtProof.builder()
                .credentialIssuerURI(CREDENTIAL_ISSUER)
                .cNonce(C_NONCE)
                .publicJwk(publicJwk)
                .keyPair(keyPair);
    }

    @Test
    void proof_whenCreated_thenHasTheHeaderAndClaimsOfTheJwtProofType() throws Exception {
        final SignedJWT proof = SignedJWT.parse(proof().build().toJwt());

        assertThat(proof.getHeader().getType().getType())
                .as("Appendix F.1: typ is openid4vci-proof+jwt")
                .isEqualTo("openid4vci-proof+jwt");
        assertThat(proof.getHeader().getAlgorithm().getName())
                .isEqualTo("ES256");
        assertThat(proof.getHeader().getJWK().toECKey().getX())
                .as("the key the Credential is bound to is in the jwk header")
                .isEqualTo(publicJwk.getX());
        assertThat(proof.getHeader().getJWK().isPrivate())
                .isFalse();
        assertThat(proof.getHeader().getKeyID())
                .as("Appendix F.1: kid MUST NOT be present when jwk is")
                .isNull();
        assertThat(proof.getHeader().getCustomParam("key_attestation"))
                .isNull();

        final JWTClaimsSet claims = proof.getJWTClaimsSet();
        assertThat(claims.getAudience())
                .as("Appendix F.1: aud is the Credential Issuer Identifier")
                .containsExactly(CREDENTIAL_ISSUER);
        assertThat(claims.getStringClaim("nonce"))
                .as("Appendix F.1: nonce is the c_nonce")
                .isEqualTo(C_NONCE);
        assertThat(claims.getIssueTime().toInstant())
                .isBetween(Instant.now().minusSeconds(60), Instant.now().plusSeconds(5));
        assertThat(claims.getClaims())
                .as("Appendix F.1: iss is omitted for an anonymous Pre-Authorized Code Flow")
                .doesNotContainKey("iss");
        assertThat(proof.verify(new ECDSAVerifier(publicJwk)))
                .isTrue();
    }

    @Test
    void proof_whenTheNonceCarriesAnInstant_thenIatIsThatInstant() throws Exception {
        final Instant nonceInstant = Instant.now().minusSeconds(30).truncatedTo(ChronoUnit.SECONDS);
        final String selfContainedNonce = UUID.randomUUID() + "::" + nonceInstant;

        final SignedJWT proof = SignedJWT.parse(proof().cNonce(selfContainedNonce).build().toJwt());

        assertThat(proof.getJWTClaimsSet().getIssueTime().toInstant())
                .as("characterization: the wallet takes iat from a nonce of the form <id>::<instant>, so the Credential Issuer's"
                        + " freshness window is measured against the instant it put in the nonce")
                .isEqualTo(nonceInstant);
        assertThat(proof.getJWTClaimsSet().getStringClaim("nonce"))
                .isEqualTo(selfContainedNonce);
    }

    @Test
    void proof_whenAKeyAttestationAuthorityIsConfigured_thenTheKeyAttestationIsInTheHeader() throws Exception {
        final MockAttestationAuthority authority = new MockAttestationAuthority(
                URI.create("https://mockserver:1080/api/v1/did/" + UUID.randomUUID()));

        final SignedJWT proof = SignedJWT.parse(proof().attestationAuthority(authority).build().toJwt());

        final SignedJWT attestation = SignedJWT.parse((String) proof.getHeader().getCustomParam("key_attestation"));
        assertThat(attestation.getHeader().getType().getType())
                .as("Appendix D.1: typ is key-attestation+jwt")
                .isEqualTo("key-attestation+jwt");
        assertThat(attestation.getHeader().getKeyID())
                .isEqualTo(authority.getKid());
        assertThat(attestation.verify(new ECDSAVerifier(authority.getSigningPublicJwk())))
                .as("signed by the attestation authority, not by the holder key")
                .isTrue();
        assertThat(attestation.getJWTClaimsSet().getExpirationTime())
                .as("Appendix D.1: exp MUST be present when the attestation is used with the jwt proof type")
                .isNotNull();
        final List<?> attestedKeys = (List<?>) attestation.getJWTClaimsSet().getClaim("attested_keys");
        assertThat(attestedKeys)
                .as("Appendix F.1: the proof is signed by a key contained in the attestation")
                .singleElement()
                .satisfies(key -> assertThat(((Map<?, ?>) key).get("x")).isEqualTo(publicJwk.getX().toString()));
    }

    @Test
    void ed25519Proof_whenCreated_thenIsSignedWithEd25519AndCarriesItsPublicKey() throws Exception {
        final OctetKeyPair edKey = new OctetKeyPairGenerator(com.nimbusds.jose.jwk.Curve.Ed25519).generate();

        final SignedJWT proof = SignedJWT.parse(JwtProof.ed25519(CREDENTIAL_ISSUER, C_NONCE, edKey).toJwt());

        assertThat(proof.getHeader().getAlgorithm().getName())
                .as("a deliberate deviation from the Swiss profile (ES256): used to check the Credential Issuer's algorithm policy")
                .isEqualTo("Ed25519");
        assertThat(proof.getHeader().getType().getType())
                .isEqualTo("openid4vci-proof+jwt");
        assertThat(proof.getHeader().getJWK().toOctetKeyPair().getX())
                .isEqualTo(edKey.getX());
        assertThat(proof.verify(new Ed25519Verifier(edKey.toPublicJWK())))
                .isTrue();
    }
}
