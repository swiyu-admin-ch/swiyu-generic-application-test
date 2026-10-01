package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact;

import ch.admin.bj.swiyu.dpop.DpopConstants;
import ch.admin.bj.swiyu.dpop.DpopJwtValidator;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto.Sha256Base64Url;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves, for every deliberate deviation of {@link DpopProof}, that it breaks exactly one DPoP requirement.
 *
 * <p>A deviation that breaks nothing gives a false green in an E2E test, and one that breaks two gives an ambiguous red.
 * The requirements are checked one by one with the DPoP validators of {@code swiyu-generic-java-lib} (reference) and, for
 * {@code ath}, with the computation of RFC 9449 §4.2 written in this repository.
 */
class DpopProofTest {

    private static final URI REQUEST_URI = URI.create("https://issuer.example.com/oid4vci/api/credential");
    private static final String NONCE = "server-provided-dpop-nonce";
    private static final String ACCESS_TOKEN = "7e3d56f6-cfc0-4d33-98ad-7147a64f8296";

    private KeyPair keyPair;
    private ECKey publicJwk;

    @BeforeEach
    void setUp() {
        keyPair = ECCryptoSupport.generateECKeyPair();
        publicJwk = ECCryptoSupport.toPublicJwk(keyPair.getPublic(), "holder-dpop-key");
    }

    private DpopProof.Builder conformant() {
        return DpopProof.forRequest("POST", REQUEST_URI.toString())
                .nonce(NONCE)
                .accessToken(ACCESS_TOKEN)
                .signedWith(keyPair, publicJwk);
    }

    /** The names of the requirements the proof does not satisfy, for a request to {@link #REQUEST_URI}. */
    private static Set<String> violations(final String proof) throws Exception {
        final SignedJWT jwt = DpopJwtValidator.parse(proof);
        final Set<String> violated = new LinkedHashSet<>();
        check(violated, "mandatory claims", () -> DpopJwtValidator.validateMandatoryClaims(jwt.getHeader(), jwt.getJWTClaimsSet()));
        check(violated, "typ", () -> DpopJwtValidator.validateTyp(jwt.getHeader()));
        check(violated, "alg", () -> DpopJwtValidator.validateAlgorithm(jwt.getHeader(), DpopConstants.SUPPORTED_ALGORITHMS));
        check(violated, "public key", () -> DpopJwtValidator.validatePublicKeyNotPrivate(jwt.getHeader().getJWK()));
        check(violated, "signature", () -> DpopJwtValidator.validateSignature(jwt, jwt.getHeader().getJWK()));
        check(violated, "htm", () -> DpopJwtValidator.validateHtm("POST", jwt.getJWTClaimsSet()));
        check(violated, "htu", () -> DpopJwtValidator.validateHtu(REQUEST_URI, jwt.getJWTClaimsSet().getStringClaim("htu"), REQUEST_URI));
        check(violated, "iat", () -> DpopJwtValidator.validateIssuedAt(jwt.getJWTClaimsSet(), 60, Clock.systemUTC()));
        final String ath = jwt.getJWTClaimsSet().getStringClaim("ath");
        if (!Sha256Base64Url.ofUsAscii(ACCESS_TOKEN).equals(ath)) {
            violated.add("ath");
        }
        return violated;
    }

    @FunctionalInterface
    private interface Check {
        void run() throws Exception;
    }

    private static void check(final Set<String> violated, final String name, final Check check) {
        try {
            check.run();
        } catch (Exception e) {
            violated.add(name);
        }
    }

    @Test
    void conformantProof_whenBuilt_thenViolatesNothing() throws Exception {
        assertThat(violations(conformant().build()))
                .isEmpty();
    }

    @Test
    void withHtu_whenAnotherUrl_thenOnlyHtuIsViolated() throws Exception {
        assertThat(violations(conformant().withHtu("http://attacker-url:8080/oid4vci/api/credential").build()))
                .containsExactly("htu");
    }

    @Test
    void withHtm_whenAnotherMethod_thenOnlyHtmIsViolated() throws Exception {
        assertThat(violations(conformant().withHtm("GET").build()))
                .containsExactly("htm");
    }

    @Test
    void withIssuedAt_whenInThePast_thenOnlyIatIsViolated() throws Exception {
        assertThat(violations(conformant().withIssuedAt(Instant.now().minusSeconds(3600)).build()))
                .containsExactly("iat");
    }

    @Test
    void withAth_whenAnotherHash_thenOnlyAthIsViolated() throws Exception {
        assertThat(violations(conformant().withAth(Sha256Base64Url.ofUsAscii("another-access-token")).build()))
                .containsExactly("ath");
    }

    @Test
    void withoutAccessToken_whenNoAthIsBuilt_thenOnlyAthIsViolatedForAnAccessTokenBoundRequest() throws Exception {
        assertThat(violations(DpopProof.forRequest("POST", REQUEST_URI.toString())
                .nonce(NONCE)
                .signedWith(keyPair, publicJwk)
                .build()))
                .containsExactly("ath");
    }

    @Test
    void withoutNonce_whenNoNonceIsGiven_thenOnlyTheMandatoryClaimsAreViolated() throws Exception {
        assertThat(violations(DpopProof.forRequest("POST", REQUEST_URI.toString())
                .accessToken(ACCESS_TOKEN)
                .signedWith(keyPair, publicJwk)
                .build()))
                .as("the Swiss profile requires the DPoP nonce (issuance §7.2); the library lists nonce as mandatory")
                .containsExactly("mandatory claims");
    }

    @Test
    void withJti_whenTheSameIdentifierIsReused_thenTheProofIsOtherwiseValid() throws Exception {
        final String reusedJti = UUID.randomUUID().toString();

        final SignedJWT first = SignedJWT.parse(conformant().withJti(reusedJti).build());
        final SignedJWT second = SignedJWT.parse(conformant().withJti(reusedJti).build());

        assertThat(first.getJWTClaimsSet().getJWTID())
                .isEqualTo(second.getJWTClaimsSet().getJWTID());
        assertThat(violations(conformant().withJti(reusedJti).build()))
                .as("replay of a jti is only detectable by a server that remembers it: nothing else is wrong")
                .isEmpty();
    }

    @Test
    void signedWithEd25519_whenUsed_thenOnlyTheAlgorithmIsViolated() throws Exception {
        final OctetKeyPair edKey = new OctetKeyPairGenerator(Curve.Ed25519).generate();

        final Set<String> violated = violations(conformant().signedWithEd25519(edKey).build());

        assertThat(violated)
                .as("Swiss profiles: JWS algorithm MUST be ES256")
                .contains("alg")
                .doesNotContain("typ", "htm", "htu", "iat", "ath", "mandatory claims");
    }
}
