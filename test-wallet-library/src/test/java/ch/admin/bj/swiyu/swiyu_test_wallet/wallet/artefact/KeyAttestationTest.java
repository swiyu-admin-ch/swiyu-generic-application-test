package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact;

import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.JwtProof;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.JOSEException;
import java.text.ParseException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves that every deliberate deviation of {@link KeyAttestation} breaks exactly one requirement of OID4VCI 1.0
 * Appendix D.1, D.2. The requirements are checked one by one, with values written from the specification.
 */
class KeyAttestationTest {

    private static final String AUTHORITY_KID = "did:tdw:example:attestation-authority#assert-key-01";
    private static final String AUTHORITY_ISS = "did:tdw:example:attestation-authority";

    private KeyPair authorityKeyPair;
    private ECKey authorityPublicKey;
    private ECKey holderPublicKey;

    @BeforeEach
    void setUp() {
        authorityKeyPair = ECCryptoSupport.generateECKeyPair();
        authorityPublicKey = ECCryptoSupport.toPublicJwk(authorityKeyPair.getPublic(), AUTHORITY_KID);
        holderPublicKey = ECCryptoSupport.toPublicJwk(ECCryptoSupport.generateECKeyPair().getPublic(), "holder-key");
    }

    private KeyAttestation.Builder conformant() {
        return KeyAttestation.forKey(holderPublicKey, "c-nonce")
                .signedBy(authorityKeyPair.getPrivate(), AUTHORITY_KID, AUTHORITY_ISS);
    }

    /** The requirements the key attestation does not satisfy. */
    // Keep the independent invariants together so each deviation's oracle remains visible.
    @SuppressWarnings({"PMD.CyclomaticComplexity", "PMD.NPathComplexity"})
    private Set<String> violations(final String keyAttestation) throws ParseException, JOSEException {
        final SignedJWT jwt = SignedJWT.parse(keyAttestation);
        final Set<String> violated = new LinkedHashSet<>();
        if (jwt.getHeader().getType() == null || !"key-attestation+jwt".equals(jwt.getHeader().getType().getType())) {
            violated.add("typ");
        }
        if (!AUTHORITY_KID.equals(jwt.getHeader().getKeyID()) || !jwt.verify(new ECDSAVerifier(authorityPublicKey))) {
            violated.add("signature");
        }
        if (!"swiss-profile-issuance:1.0.0".equals(jwt.getHeader().getCustomParam("profile_version"))) {
            violated.add("profile_version");
        }
        if (!"c-nonce".equals(jwt.getJWTClaimsSet().getStringClaim("nonce"))) {
            violated.add("nonce");
        }
        if (!jwt.getJWTClaimsSet().getExpirationTime().toInstant()
                .equals(jwt.getJWTClaimsSet().getIssueTime().toInstant().plusSeconds(12 * 60 * 60))) {
            violated.add("lifetime");
        }
        final Instant now = Instant.now();
        if (jwt.getJWTClaimsSet().getIssueTime().toInstant().isAfter(now.plusSeconds(60))) {
            violated.add("iat");
        }
        if (!jwt.getJWTClaimsSet().getExpirationTime().toInstant().isAfter(now)) {
            violated.add("exp");
        }
        if (!List.of("iso_18045_high").equals(jwt.getJWTClaimsSet().getStringListClaim("key_storage"))) {
            violated.add("key_storage");
        }
        final List<Object> attestedKeys = jwt.getJWTClaimsSet().getListClaim("attested_keys");
        if (attestedKeys.size() != 1 || !ECKey.parse((Map<String, Object>) attestedKeys.getFirst()).computeThumbprint()
                .equals(holderPublicKey.computeThumbprint())) {
            violated.add("attested_keys");
        }
        return violated;
    }

    @Test
    void conformantKeyAttestation_whenBuilt_thenViolatesNothing() throws Exception {
        assertThat(violations(conformant().build()))
                .isEmpty();
    }

    @Test
    void withAttestedKey_whenAnotherKey_thenOnlyAttestedKeysIsViolated() throws Exception {
        final ECKey otherKey = ECCryptoSupport.toPublicJwk(ECCryptoSupport.generateECKeyPair().getPublic(), "other");

        assertThat(violations(conformant().withAttestedKey(otherKey).build()))
                .containsExactly("attested_keys");
    }

    @Test
    void withKeyStorage_whenEnhancedBasic_thenOnlyKeyStorageIsViolated() throws Exception {
        final String attestation = conformant().withKeyStorage(KeyAttestation.LEVEL_ENHANCED_BASIC).build();
        assertThat(SignedJWT.parse(attestation).getJWTClaimsSet().getStringListClaim("key_storage"))
                .containsExactly("iso_18045_enhanced-basic");
        assertThat(violations(attestation))
                .containsExactly("key_storage");
    }

    @Test
    void withExpiration_whenInThePast_thenOnlyExpIsViolated() throws Exception {
        assertThat(violations(conformant().withExpiration(Instant.now().minusSeconds(3600)).build()))
                .containsExactly("exp");
    }

    @Test
    void keyProof_whenGivenAKeyAttestation_thenCarriesItInTheKeyAttestationHeader() throws Exception {
        final KeyPair holderKeyPair = ECCryptoSupport.generateECKeyPair();
        final ECKey holderKey = ECCryptoSupport.toPublicJwk(holderKeyPair.getPublic(), "holder-key");
        final String attestation = KeyAttestation.forKey(holderKey, "n")
                .signedBy(authorityKeyPair.getPrivate(), AUTHORITY_KID, AUTHORITY_ISS)
                .build();

        final SignedJWT proof = SignedJWT.parse(JwtProof.builder().credentialIssuerURI("https://issuer.example.com").cNonce("n")
                .keyPair(holderKeyPair).publicJwk(holderKey)
                .keyAttestation(attestation)
                .build().toJwt());

        assertThat(proof.getHeader().getCustomParam("key_attestation"))
                .isEqualTo(attestation);
    }
}
