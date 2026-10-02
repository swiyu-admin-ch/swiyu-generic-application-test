package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact;

import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto.Sha256Base64Url;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * A DPoP proof JWT (RFC 9449 §4.2), conformant by default.
 *
 * <p>Out of the box a proof has {@code typ} {@code dpop+jwt}, {@code alg} ES256, the public key of the signing key in the
 * {@code jwk} header, a fresh {@code jti}, {@code htm}, {@code htu}, {@code iat} set to now, the {@code nonce} when one is
 * given, and {@code ath} when an access token is given (Swiss issuance profile §3.5, §8.2, §9: a DPoP header on token,
 * credential, and deferred requests).
 *
 * <p>Every method under "Deliberate deviations" breaks exactly one requirement and leaves the others satisfied; the unit
 * tests prove that against the DPoP validators of {@code swiyu-generic-java-lib}. Name the deviation in the test that uses it.
 *
 * <pre>{@code
 * DpopProof.forRequest("POST", tokenUri).nonce(nonce).signedWith(keyPair, publicJwk).build();
 * DpopProof.forRequest("POST", credentialUri).nonce(n).accessToken(t).signedWith(kp, jwk).withHtu(attackerUri).build();
 * }</pre>
 */
public final class DpopProof {

    private static final String TYP = "dpop+jwt";

    private DpopProof() {
    }

    public static Builder forRequest(final String httpMethod, final String httpUri) {
        return new Builder(httpMethod, httpUri);
    }

    public static final class Builder {

        private String htm;
        private String htu;
        private String nonce;
        private String accessToken;
        private String athOverride;
        private Instant issuedAt = Instant.now();
        private String jti = UUID.randomUUID().toString();
        private KeyPair keyPair;
        private ECKey publicJwk;
        private OctetKeyPair ed25519Key;

        private Builder(final String httpMethod, final String httpUri) {
            this.htm = httpMethod;
            this.htu = httpUri;
        }

        /** The server-provided DPoP nonce ({@code DPoP-Nonce}, RFC 9449 §8). */
        public Builder nonce(final String nonce) {
            this.nonce = nonce;
            return this;
        }

        /** Binds the proof to this access token with {@code ath} (RFC 9449 §4.2). */
        public Builder accessToken(final String accessToken) {
            this.accessToken = accessToken;
            return this;
        }

        /** The key that signs the proof and whose public part goes in the {@code jwk} header. */
        public Builder signedWith(final KeyPair keyPair, final ECKey publicJwk) {
            this.keyPair = keyPair;
            this.publicJwk = publicJwk;
            return this;
        }

        // ---- Deliberate deviations: each breaks one requirement ----

        /** {@code htu} is another URL than the one the request goes to (RFC 9449 §4.3, a hijacked proof). */
        public Builder withHtu(final String otherUri) {
            this.htu = otherUri;
            return this;
        }

        /** {@code htm} is another HTTP method than the one of the request (RFC 9449 §4.3). */
        public Builder withHtm(final String otherMethod) {
            this.htm = otherMethod;
            return this;
        }

        /** {@code iat} is at this instant instead of now (RFC 9449 §4.3: the proof must be recent). */
        public Builder withIssuedAt(final Instant instant) {
            this.issuedAt = instant;
            return this;
        }

        /** {@code jti} is this value instead of a fresh one, to replay an identifier (RFC 9449 §11.1). */
        public Builder withJti(final String jti) {
            this.jti = jti;
            return this;
        }

        /** {@code ath} is this value instead of the hash of the access token (RFC 9449 §4.2). */
        public Builder withAth(final String ath) {
            this.athOverride = ath;
            return this;
        }

        /** Signs with Ed25519 and puts the OKP public key in {@code jwk}: not ES256, which the Swiss profiles require. */
        public Builder signedWithEd25519(final OctetKeyPair key) {
            this.ed25519Key = key;
            return this;
        }

        public String build() {
            try {
                final boolean ed25519 = ed25519Key != null;
                final JWSHeader header = new JWSHeader.Builder(ed25519 ? JWSAlgorithm.Ed25519 : JWSAlgorithm.ES256)
                        .type(new JOSEObjectType(TYP))
                        .jwk(ed25519 ? ed25519Key.toPublicJWK() : publicJwk)
                        .build();

                final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                        .jwtID(jti)
                        .claim("htm", htm)
                        .claim("htu", htu)
                        .issueTime(Date.from(issuedAt));
                if (nonce != null) {
                    claims.claim("nonce", nonce);
                }
                if (athOverride != null) {
                    claims.claim("ath", athOverride);
                } else if (accessToken != null) {
                    claims.claim("ath", Sha256Base64Url.ofUsAscii(accessToken));
                }

                final JWSSigner signer = ed25519
                        ? new Ed25519Signer(ed25519Key)
                        : ECCryptoSupport.createECDSASigner(keyPair.getPrivate());
                final SignedJWT jwt = new SignedJWT(header, claims.build());
                jwt.sign(signer);
                return jwt.serialize();
            } catch (JOSEException e) {
                throw new IllegalStateException("Failed to create DPoP proof", e);
            }
        }
    }
}
