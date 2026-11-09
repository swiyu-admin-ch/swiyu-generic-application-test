package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact;

import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * A key attestation JWT (OID4VCI 1.0 Appendix D.1), sent in the {@code key_attestation} header of a key proof, conformant
 * by default.
 *
 * <p>Out of the box: {@code typ} {@code key-attestation+jwt}, {@code alg} ES256, the {@code kid} of the attestation
 * authority's key, {@code iss} as given, {@code iat} now, {@code exp} twelve hours later, {@code key_storage}
 * {@code iso_18045_high} and {@code attested_keys} holding exactly the attested public key. The Swiss issuance profile
 * Appendix D.1 requires {@code profile_version} and a twelve-hour lifetime; OID4VCI F.1 requires the provided nonce.
 *
 * <p>Every method under "Deliberate deviations" breaks exactly one requirement; {@code KeyAttestationTest} proves it.
 *
 * <pre>{@code
 * KeyAttestation.forKey(holderPublicKey, cNonce).signedBy(signingKey, kid, issuer).withKeyStorage(LEVEL_ENHANCED_BASIC).build();
 * }</pre>
 */
public final class KeyAttestation {

    public static final String LEVEL_HIGH = "iso_18045_high";
    public static final String LEVEL_ENHANCED_BASIC = "iso_18045_enhanced-basic";

    private static final String TYP = "key-attestation+jwt";
    private static final Duration LIFETIME = Duration.ofHours(12);

    private KeyAttestation() {
    }

    /** @param attestedKey the public holder key the attestation vouches for */
    public static Builder forKey(final ECKey attestedKey, final String cNonce) {
        return new Builder(attestedKey, cNonce);
    }

    public static final class Builder {

        private ECKey attestedKey;
        private String keyStorage = LEVEL_HIGH;
        private Instant issuedAt = Instant.now();
        private Instant expiresAt = issuedAt.plus(LIFETIME);
        private PrivateKey signingKey;
        private String keyId;
        private String issuer;
        private final String nonce;

        private Builder(final ECKey attestedKey, final String cNonce) {
            this.attestedKey = attestedKey;
            this.nonce = cNonce;
        }

        /**
         * The attestation authority: its signing key, the {@code kid} (DID URL) the Issuer resolves, and the {@code iss}.
         */
        public Builder signedBy(final PrivateKey signingKey, final String keyId, final String issuer) {
            this.signingKey = signingKey;
            this.keyId = keyId;
            this.issuer = issuer;
            return this;
        }

        // ---- Deliberate deviations: each breaks one requirement ----

        /** {@code attested_keys} holds another key than the one the key proof is signed with (OID4VCI Appendix D.1, F.1). */
        public Builder withAttestedKey(final ECKey otherKey) {
            this.attestedKey = otherKey;
            return this;
        }

        /** {@code key_storage} is this level, e.g. below the {@code key_attestations_required} of the configuration (Appendix D.2). */
        public Builder withKeyStorage(final String level) {
            this.keyStorage = level;
            return this;
        }

        /** {@code exp} is at this instant, e.g. in the past (OID4VCI Appendix D.1, RFC 7519 §4.1.4). */
        public Builder withExpiration(final Instant instant) {
            this.expiresAt = instant;
            this.issuedAt = instant.minus(LIFETIME);
            return this;
        }

        public String build() {
            try {
                final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType(TYP))
                        .keyID(keyId)
                        .customParam("profile_version", "swiss-profile-issuance:1.0.0")
                        .build();
                final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                        .issuer(issuer)
                        .issueTime(Date.from(issuedAt))
                        .expirationTime(Date.from(expiresAt))
                        .claim("nonce", nonce)
                        .claim("key_storage", List.of(keyStorage))
                        .claim("attested_keys", List.of(attestedKey.toPublicJWK().toJSONObject()))
                        .build();
                final SignedJWT jwt = new SignedJWT(header, claims);
                jwt.sign(ECCryptoSupport.createECDSASigner(signingKey));
                return jwt.serialize();
            } catch (JOSEException e) {
                throw new IllegalStateException("Failed to create the key attestation", e);
            }
        }
    }
}
