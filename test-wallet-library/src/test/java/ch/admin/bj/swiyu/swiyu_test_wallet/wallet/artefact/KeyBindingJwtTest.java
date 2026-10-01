package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact;

import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.Sha256Base64Url;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves that every deliberate deviation of {@link KeyBindingJwt} breaks exactly one requirement of RFC 9901 §4.3 and
 * OID4VP 1.0 Appendix B.3.6. The requirements are checked one by one, with values written from the specifications.
 */
class KeyBindingJwtTest {

    private static final String AUDIENCE = "decentralized_identifier:did:tdw:example:verifier";
    private static final String NONCE = "n-0S6_WzA2Mj";
    private static final String PRESENTED_SD_JWT = "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ4In0.c2ln~WyJzYWx0IiwibmFtZSIsIkpvaG4iXQ~";

    private KeyPair holderKeyPair;
    private ECKey holderPublicKey;

    @BeforeEach
    void setUp() {
        holderKeyPair = ECCryptoSupport.generateECKeyPair();
        holderPublicKey = ECCryptoSupport.toPublicJwk(holderKeyPair.getPublic(), "holder-key");
    }

    private KeyBindingJwt.Builder conformant() {
        return KeyBindingJwt.forPresentation(PRESENTED_SD_JWT, AUDIENCE, NONCE).signedWith(holderKeyPair);
    }

    /** The requirements the Key Binding JWT does not satisfy. */
    private Set<String> violations(final String keyBindingJwt) throws Exception {
        final SignedJWT jwt = SignedJWT.parse(keyBindingJwt);
        final Set<String> violated = new LinkedHashSet<>();
        if (jwt.getHeader().getType() == null || !"kb+jwt".equals(jwt.getHeader().getType().getType())) {
            violated.add("typ");
        }
        if (!"ES256".equals(jwt.getHeader().getAlgorithm().getName())) {
            violated.add("alg");
        }
        if (!jwt.verify(new ECDSAVerifier(holderPublicKey))) {
            violated.add("signature");
        }
        if (!jwt.getJWTClaimsSet().getAudience().equals(java.util.List.of(AUDIENCE))) {
            violated.add("aud");
        }
        if (!NONCE.equals(jwt.getJWTClaimsSet().getStringClaim("nonce"))) {
            violated.add("nonce");
        }
        if (!Sha256Base64Url.ofUsAscii(PRESENTED_SD_JWT).equals(jwt.getJWTClaimsSet().getStringClaim("sd_hash"))) {
            violated.add("sd_hash");
        }
        final Instant iat = jwt.getJWTClaimsSet().getIssueTime().toInstant();
        if (iat.isBefore(Instant.now().minusSeconds(60)) || iat.isAfter(Instant.now().plusSeconds(60))) {
            violated.add("iat");
        }
        return violated;
    }

    @Test
    void conformantKeyBindingJwt_whenBuilt_thenViolatesNothing() throws Exception {
        assertThat(violations(conformant().build()))
                .isEmpty();
    }

    @Test
    void withAudience_whenAnotherReceiver_thenOnlyAudIsViolated() throws Exception {
        assertThat(violations(conformant().withAudience("decentralized_identifier:did:tdw:example:other").build()))
                .containsExactly("aud");
    }

    @Test
    void withNonce_whenNotTheRequestNonce_thenOnlyNonceIsViolated() throws Exception {
        assertThat(violations(conformant().withNonce("another-nonce").build()))
                .containsExactly("nonce");
    }

    @Test
    void withSdHash_whenAnotherSdJwt_thenOnlySdHashIsViolated() throws Exception {
        assertThat(violations(conformant().withSdHash(Sha256Base64Url.ofUsAscii("another presentation~")).build()))
                .containsExactly("sd_hash");
    }

    @Test
    void withIssuedAt_whenInThePast_thenOnlyIatIsViolated() throws Exception {
        assertThat(violations(conformant().withIssuedAt(Instant.now().minusSeconds(3600)).build()))
                .containsExactly("iat");
    }

    @Test
    void signedWithEd25519_whenUsed_thenIsSignedWithEd25519AndOtherwiseConformant() throws Exception {
        final OctetKeyPair holderKey = new OctetKeyPairGenerator(Curve.Ed25519).generate();

        final SignedJWT jwt = SignedJWT.parse(conformant().signedWithEd25519(holderKey).build());

        assertThat(jwt.getHeader().getAlgorithm().getName())
                .as("Swiss profiles: ES256")
                .isEqualTo("Ed25519");
        assertThat(jwt.verify(new Ed25519Verifier(holderKey.toPublicJWK())))
                .isTrue();
        assertThat(jwt.getJWTClaimsSet().getStringClaim("sd_hash"))
                .isEqualTo(Sha256Base64Url.ofUsAscii(PRESENTED_SD_JWT));
        assertThat(jwt.getJWTClaimsSet().getStringClaim("nonce"))
                .isEqualTo(NONCE);
    }
}
