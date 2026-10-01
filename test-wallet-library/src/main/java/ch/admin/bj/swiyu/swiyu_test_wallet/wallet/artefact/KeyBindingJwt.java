package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact;

import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto.Sha256Base64Url;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;

/**
 * The Key Binding JWT of an SD-JWT presentation (RFC 9901 §4.3), conformant by default.
 *
 * <p>Out of the box: {@code typ} {@code kb+jwt}, {@code alg} ES256, {@code iat} now, {@code aud} and {@code nonce} as given
 * (OID4VP 1.0 Appendix B.3.6: the Client Identifier and the nonce of the Authorization Request), and {@code sd_hash} computed
 * over the US-ASCII bytes of the presented SD-JWT up to and including its last tilde (RFC 9901 §4.3.1).
 *
 * <p>Every method under "Deliberate deviations" breaks exactly one requirement; {@code KeyBindingJwtTest} proves it.
 */
public final class KeyBindingJwt {

    private static final String TYP = "kb+jwt";

    private KeyBindingJwt() {
    }

    /**
     * @param sdJwtWithoutKeyBinding the presented SD-JWT, {@code <Issuer-signed JWT>~<D1>~...~<DN>~}
     * @param audience               the {@code aud}: the full Client Identifier of the Verifier
     * @param nonce                  the {@code nonce} of the Authorization Request
     */
    public static Builder forPresentation(final String sdJwtWithoutKeyBinding, final String audience, final String nonce) {
        return new Builder(sdJwtWithoutKeyBinding, audience, nonce);
    }

    public static final class Builder {

        private final String sdJwt;
        private String audience;
        private String nonce;
        private String sdHash;
        private Instant issuedAt = Instant.now();
        private KeyPair keyPair;
        private OctetKeyPair ed25519Key;

        private Builder(final String sdJwt, final String audience, final String nonce) {
            this.sdJwt = sdJwt;
            this.audience = audience;
            this.nonce = nonce;
            this.sdHash = Sha256Base64Url.ofUsAscii(sdJwt);
        }

        /** The holder key bound in the credential's {@code cnf} (ES256, the Swiss profile). */
        public Builder signedWith(final KeyPair holderKey) {
            this.keyPair = holderKey;
            return this;
        }

        // ---- Deliberate deviations: each breaks one requirement ----

        /** {@code aud} is another receiver than the Verifier that asked (OID4VP B.3.6, §14.8). */
        public Builder withAudience(final String audience) {
            this.audience = audience;
            return this;
        }

        /** {@code nonce} is not the nonce of the Authorization Request (OID4VP B.3.6, RFC 9901 §4.3: freshness). */
        public Builder withNonce(final String nonce) {
            this.nonce = nonce;
            return this;
        }

        /** {@code sd_hash} does not match the presented SD-JWT (RFC 9901 §4.3.1). */
        public Builder withSdHash(final String sdHash) {
            this.sdHash = sdHash;
            return this;
        }

        /** {@code iat} is at this instant instead of now (RFC 9901 §4.3, §7.3: the proof must be recent). */
        public Builder withIssuedAt(final Instant instant) {
            this.issuedAt = instant;
            return this;
        }

        /** Signs with an Ed25519 holder key: not ES256, which the Swiss profiles require. */
        public Builder signedWithEd25519(final OctetKeyPair holderKey) {
            this.ed25519Key = holderKey;
            return this;
        }

        /** The compact Key Binding JWT, to be appended to the presented SD-JWT. */
        public String build() {
            try {
                final boolean ed25519 = ed25519Key != null;
                final JWSHeader header = new JWSHeader.Builder(ed25519 ? JWSAlgorithm.Ed25519 : JWSAlgorithm.ES256)
                        .type(new JOSEObjectType(TYP))
                        .build();
                final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                        .claim("sd_hash", sdHash)
                        .audience(audience)
                        .claim("nonce", nonce)
                        .issueTime(Date.from(issuedAt))
                        .build();
                final JWSSigner signer = ed25519
                        ? new Ed25519Signer(ed25519Key)
                        : ECCryptoSupport.createECDSASigner(keyPair.getPrivate());
                final SignedJWT jwt = new SignedJWT(header, claims);
                jwt.sign(signer);
                return jwt.serialize();
            } catch (JOSEException e) {
                throw new IllegalStateException("Failed to create the Key Binding JWT", e);
            }
        }
    }
}
