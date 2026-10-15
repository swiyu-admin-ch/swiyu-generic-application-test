package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact;

import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.KeyPair;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * An SD-JWT, issued credential or presentation, as {@code <Issuer-signed JWT>~<D1>~...~<DN>~[<Key Binding JWT>]}
 * (RFC 9901 §4), with the operations tests need to turn it into something a Verifier must reject or must handle with care.
 *
 * <p>The value is immutable: every method returns a new credential. Each deviation breaks exactly one requirement
 * ({@code SdJwtCredentialTest} proves it) and says so in its name.
 */
public final class SdJwtCredential {

    private static final String SEPARATOR = "~";

    private final String issuerSignedJwt;
    private final List<String> disclosures;
    private final String keyBindingJwt;

    private SdJwtCredential(final String issuerSignedJwt, final List<String> disclosures, final String keyBindingJwt) {
        this.issuerSignedJwt = issuerSignedJwt;
        this.disclosures = List.copyOf(disclosures);
        this.keyBindingJwt = keyBindingJwt;
    }

    public static SdJwtCredential parse(final String serialized) {
        if (!serialized.contains(SEPARATOR)) {
            throw new IllegalArgumentException("An SD-JWT has at least one tilde (RFC 9901 §4)");
        }
        final String[] parts = serialized.split(SEPARATOR, -1);
        final boolean hasKeyBinding = !serialized.endsWith(SEPARATOR);
        final int disclosuresEnd = parts.length - 1;
        final List<String> disclosures = new ArrayList<>();
        for (int i = 1; i < disclosuresEnd; i++) {
            disclosures.add(parts[i]);
        }
        return new SdJwtCredential(parts[0], disclosures, hasKeyBinding ? parts[parts.length - 1] : null);
    }

    public String issuerSignedJwt() {
        return issuerSignedJwt;
    }

    public List<String> disclosures() {
        return disclosures;
    }

    public Optional<String> keyBindingJwt() {
        return Optional.ofNullable(keyBindingJwt);
    }

    /** {@code <Issuer-signed JWT>~<D1>~...~<DN>~}, what the Key Binding JWT's {@code sd_hash} covers. */
    public String withoutKeyBinding() {
        final StringBuilder text = new StringBuilder(issuerSignedJwt).append(SEPARATOR);
        disclosures.forEach(d -> text.append(d).append(SEPARATOR));
        return text.toString();
    }

    public String serialize() {
        return withoutKeyBinding() + (keyBindingJwt == null ? "" : keyBindingJwt);
    }

    /** This credential followed by a Key Binding JWT, i.e. a presentation. */
    public SdJwtCredential presentedWith(final String keyBindingJwt) {
        return new SdJwtCredential(issuerSignedJwt, disclosures, keyBindingJwt);
    }

    // ---- Deliberate deviations: each breaks one requirement ----

    /** The signature of the Issuer-signed JWT no longer verifies; header, claims and Disclosures are untouched. */
    public SdJwtCredential withCorruptedIssuerSignature() {
        return new SdJwtCredential(corruptSignature(issuerSignedJwt), disclosures, keyBindingJwt);
    }

    /** The signature of the Key Binding JWT no longer verifies; everything else is untouched. */
    public SdJwtCredential withCorruptedKeyBindingSignature() {
        if (keyBindingJwt == null) {
            throw new IllegalStateException("There is no Key Binding JWT to corrupt");
        }
        return new SdJwtCredential(issuerSignedJwt, disclosures, corruptSignature(keyBindingJwt));
    }

    /**
     * Signs the Issuer-signed JWT again, with another key and/or with some claims changed. The header (including
     * {@code typ} and {@code profile_version}) and the claims are kept unless the caller changes them.
     */
    public Resign resign() {
        return new Resign(this);
    }

    private static String corruptSignature(final String compactJws) {
        final String[] parts = compactJws.split("\\.", -1);
        if (parts.length != 3 || parts[2].isEmpty()) {
            throw new IllegalArgumentException("A compact JWS with a signature is required");
        }
        final char replacement = parts[2].charAt(0) == 'A' ? 'B' : 'A';
        parts[2] = replacement + parts[2].substring(1);
        return String.join(".", parts);
    }

    public static final class Resign {

        private final SdJwtCredential source;
        private String keyId;
        private String issuer;
        private boolean withoutIssuer;
        private JWK holderKey;
        private boolean withoutStatus;
        private KeyPair ecKey;
        private OctetKeyPair ed25519Key;

        private Resign(final SdJwtCredential source) {
            this.source = source;
        }

        /** Signs with this P-256 key (ES256). */
        public Resign signedWith(final KeyPair signingKey) {
            this.ecKey = signingKey;
            return this;
        }

        /** Signs with this Ed25519 key, and the {@code alg} header becomes Ed25519. */
        public Resign signedWithEd25519(final OctetKeyPair signingKey) {
            this.ed25519Key = signingKey;
            return this;
        }

        /** The {@code kid} header: the DID URL of the key the Verifier must resolve. */
        public Resign keyId(final String keyId) {
            this.keyId = keyId;
            return this;
        }

        /** The {@code iss} claim. The Swiss anchor profile says {@code iss} must be ignored; trust follows the {@code kid}. */
        public Resign issuer(final String issuer) {
            this.issuer = issuer;
            return this;
        }

        /** Drops the {@code iss} claim. The Swiss anchor profile says trust follows the {@code kid}, so the claim may be absent. */
        public Resign withoutIssuer() {
            this.withoutIssuer = true;
            return this;
        }

        /** Binds the credential to this key through {@code cnf.jwk} (RFC 9901 §4.1.2). */
        public Resign holderKey(final JWK holderKey) {
            this.holderKey = holderKey;
            return this;
        }

        /** Drops the {@code status} claim so no Status List has to be resolved for the credential. */
        public Resign withoutStatus() {
            this.withoutStatus = true;
            return this;
        }

        public SdJwtCredential build() {
            try {
                final SignedJWT original = SignedJWT.parse(source.issuerSignedJwt);
                final JWSAlgorithm algorithm = ed25519Key != null ? JWSAlgorithm.Ed25519 : JWSAlgorithm.ES256;
                final JWSHeader.Builder newHeader = new JWSHeader.Builder(algorithm)
                        .type(original.getHeader().getType())
                        .keyID(keyId != null ? keyId : original.getHeader().getKeyID())
                        .customParams(original.getHeader().getCustomParams());

                if (issuer != null && withoutIssuer) {
                    throw new IllegalStateException("issuer(...) and withoutIssuer() contradict each other");
                }
                final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder(original.getJWTClaimsSet());
                if (issuer != null) {
                    claims.issuer(issuer);
                }
                if (withoutIssuer) {
                    claims.claim("iss", null);
                }
                if (holderKey != null) {
                    claims.claim("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()));
                }
                if (withoutStatus) {
                    claims.claim("status", null);
                }

                final JWSSigner signer;
                if (ed25519Key != null) {
                    signer = new Ed25519Signer(ed25519Key);
                } else if (ecKey != null) {
                    signer = ECCryptoSupport.createECDSASigner(ecKey.getPrivate());
                } else {
                    throw new IllegalStateException("A signing key is required: signedWith(...) or signedWithEd25519(...)");
                }
                final SignedJWT jwt = new SignedJWT(newHeader.build(), claims.build());
                jwt.sign(signer);
                return new SdJwtCredential(jwt.serialize(), source.disclosures, source.keyBindingJwt);
            } catch (ParseException | JOSEException e) {
                throw new IllegalStateException("Failed to sign the Issuer-signed JWT again", e);
            }
        }
    }
}
