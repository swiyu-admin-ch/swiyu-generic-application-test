package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact;

import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
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
    private static final Gson GSON = new Gson();
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String signedIssuerJwt;
    private final List<String> disclosureValues;
    private final String holderBindingJwt;

    private SdJwtCredential(final String signedIssuerJwt, final List<String> disclosureValues, final String holderBindingJwt) {
        this.signedIssuerJwt = signedIssuerJwt;
        this.disclosureValues = List.copyOf(disclosureValues);
        this.holderBindingJwt = holderBindingJwt;
    }

    public static SdJwtCredential parse(final String serialized) {
        if (!serialized.contains(SEPARATOR)) {
            throw new IllegalArgumentException("An SD-JWT has at least one tilde (RFC 9901 §4)");
        }
        final String[] parts = serialized.split(SEPARATOR, -1);
        final boolean hasKeyBinding = !serialized.endsWith(SEPARATOR);
        final int disclosuresEnd = parts.length - 1;
        final List<String> disclosureValues = new ArrayList<>();
        for (int i = 1; i < disclosuresEnd; i++) {
            disclosureValues.add(parts[i]);
        }
        return new SdJwtCredential(parts[0], disclosureValues, hasKeyBinding ? parts[parts.length - 1] : null);
    }

    public String issuerSignedJwt() {
        return signedIssuerJwt;
    }

    public List<String> disclosures() {
        return disclosureValues;
    }

    public Optional<String> keyBindingJwt() {
        return Optional.ofNullable(holderBindingJwt);
    }

    /** {@code <Issuer-signed JWT>~<D1>~...~<DN>~}, what the Key Binding JWT's {@code sd_hash} covers. */
    public String withoutKeyBinding() {
        final StringBuilder text = new StringBuilder(signedIssuerJwt).append(SEPARATOR);
        disclosureValues.forEach(d -> text.append(d).append(SEPARATOR));
        return text.toString();
    }

    public String serialize() {
        return withoutKeyBinding() + (holderBindingJwt == null ? "" : holderBindingJwt);
    }

    /** This credential followed by a Key Binding JWT, i.e. a presentation. */
    public SdJwtCredential presentedWith(final String holderBindingJwt) {
        return new SdJwtCredential(signedIssuerJwt, disclosureValues, holderBindingJwt);
    }

    // ---- Deliberate deviations: each breaks one requirement ----

    /** The signature of the Issuer-signed JWT no longer verifies; header, claims and Disclosures are untouched. */
    public SdJwtCredential withCorruptedIssuerSignature() {
        return new SdJwtCredential(corruptSignature(signedIssuerJwt), disclosureValues, holderBindingJwt);
    }

    /** The signature of the Key Binding JWT no longer verifies; everything else is untouched. */
    public SdJwtCredential withCorruptedKeyBindingSignature() {
        if (holderBindingJwt == null) {
            throw new IllegalStateException("There is no Key Binding JWT to corrupt");
        }
        return new SdJwtCredential(signedIssuerJwt, disclosureValues, corruptSignature(holderBindingJwt));
    }

    /** Changes one Disclosure value without updating its signed digest (RFC 9901 §7.1). */
    public SdJwtCredential withTamperedDisclosure(final String claimName, final Object forgedValue) {
        final List<String> tampered = new ArrayList<>(disclosureValues);
        for (int index = 0; index < disclosureValues.size(); index++) {
            final List<Object> disclosure = decodeDisclosure(disclosureValues.get(index));
            if (disclosure.size() == 3 && claimName.equals(disclosure.get(1))) {
                tampered.set(index, encodeDisclosure(List.of(disclosure.getFirst(), claimName, forgedValue)));
                return new SdJwtCredential(signedIssuerJwt, tampered, holderBindingJwt);
            }
        }
        throw new IllegalArgumentException("There is no Disclosure of the claim " + claimName);
    }

    /** Adds a well-formed Disclosure without a corresponding signed digest (RFC 9901 §7.1). */
    public SdJwtCredential withUnreferencedDisclosure(final String claimName, final Object value) {
        final byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        final List<String> extended = new ArrayList<>(disclosureValues);
        extended.add(encodeDisclosure(List.of(Base64URL.encode(salt).toString(), claimName, value)));
        return new SdJwtCredential(signedIssuerJwt, extended, holderBindingJwt);
    }

    @SuppressWarnings("unchecked")
    private static List<Object> decodeDisclosure(final String disclosure) {
        return GSON.fromJson(new Base64URL(disclosure).decodeToString(), List.class);
    }

    private static String encodeDisclosure(final List<Object> disclosure) {
        return Base64URL.encode(GSON.toJson(disclosure)).toString();
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
        private String signingKeyId;
        private String issuerClaim;
        private boolean omitIssuerClaim;
        private JWK holderPublicKey;
        private boolean omitCredentialStatus;
        private Instant expirationInstant;
        private Instant notBeforeInstant;
        private Integer statusIndex;
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
        public Resign keyId(final String signingKeyId) {
            this.signingKeyId = signingKeyId;
            return this;
        }

        /** The {@code iss} claim. The Swiss anchor profile says {@code iss} must be ignored; trust follows the {@code kid}. */
        public Resign issuer(final String issuerClaim) {
            this.issuerClaim = issuerClaim;
            return this;
        }

        /** Drops the {@code iss} claim. The Swiss anchor profile says trust follows the {@code kid}, so the claim may be absent. */
        public Resign withoutIssuer() {
            this.omitIssuerClaim = true;
            return this;
        }

        /** Binds the credential to this key through {@code cnf.jwk} (RFC 9901 §4.1.2). */
        public Resign holderKey(final JWK holderPublicKey) {
            this.holderPublicKey = holderPublicKey;
            return this;
        }

        /** Drops the {@code status} claim so no Status List has to be resolved for the credential. */
        public Resign withoutStatus() {
            this.omitCredentialStatus = true;
            return this;
        }

        /** Sets exp to exercise credential expiry (RFC 7519 §4.1.4). */
        public Resign expiresAt(final Instant instant) {
            this.expirationInstant = instant;
            return this;
        }

        /** Sets nbf to exercise credentials that are not valid yet (RFC 7519 §4.1.5). */
        public Resign notBefore(final Instant instant) {
            this.notBeforeInstant = instant;
            return this;
        }

        /** Changes only status.status_list.idx, keeping the registry URI (Token Status List draft 20 §8.3). */
        public Resign withStatusIndex(final int index) {
            this.statusIndex = index;
            return this;
        }

        public SdJwtCredential build() {
            try {
                final SignedJWT original = SignedJWT.parse(source.signedIssuerJwt);
                final JWSAlgorithm algorithm = ed25519Key != null ? JWSAlgorithm.Ed25519 : JWSAlgorithm.ES256;
                final JWSHeader.Builder newHeader = new JWSHeader.Builder(algorithm)
                        .type(original.getHeader().getType())
                        .keyID(signingKeyId != null ? signingKeyId : original.getHeader().getKeyID())
                        .customParams(original.getHeader().getCustomParams());

                final JWTClaimsSet.Builder claims = resigningClaims(original);
                final JWSSigner signer = resigningSigner();
                final SignedJWT jwt = new SignedJWT(newHeader.build(), claims.build());
                jwt.sign(signer);
                return new SdJwtCredential(jwt.serialize(), source.disclosureValues, source.holderBindingJwt);
            } catch (ParseException | JOSEException e) {
                throw new IllegalStateException("Failed to sign the Issuer-signed JWT again", e);
            }
        }

        private JWTClaimsSet.Builder resigningClaims(final SignedJWT original) throws ParseException {
            if (issuerClaim != null && omitIssuerClaim) {
                throw new IllegalStateException("issuer(...) and withoutIssuer() contradict each other");
            }
            final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder(original.getJWTClaimsSet());
            if (issuerClaim != null) {
                claims.issuer(issuerClaim);
            }
            if (omitIssuerClaim) {
                claims.claim("iss", null);
            }
            if (holderPublicKey != null) {
                claims.claim("cnf", Map.of("jwk", holderPublicKey.toPublicJWK().toJSONObject()));
            }
            if (omitCredentialStatus) {
                claims.claim("status", null);
            }
            applyValidityClaims(claims);
            if (statusIndex != null) {
                claims.claim("status", statusWithIndex(original.getJWTClaimsSet().getJSONObjectClaim("status")));
            }
            return claims;
        }

        private void applyValidityClaims(final JWTClaimsSet.Builder claims) {
            if (expirationInstant != null) {
                claims.expirationTime(Date.from(expirationInstant));
            }
            if (notBeforeInstant != null) {
                claims.notBeforeTime(Date.from(notBeforeInstant));
            }
        }

        private Map<String, Object> statusWithIndex(final Map<String, Object> originalStatus) {
            if (omitCredentialStatus || originalStatus == null
                    || !(originalStatus.get("status_list") instanceof Map<?, ?> originalList)) {
                throw new IllegalStateException("A status.status_list claim is required to change its index");
            }
            final Map<String, Object> statusList = new LinkedHashMap<>();
            originalList.forEach((key, value) -> statusList.put((String) key, value));
            statusList.put("idx", statusIndex);
            final Map<String, Object> status = new LinkedHashMap<>(originalStatus);
            status.put("status_list", statusList);
            return status;
        }

        private JWSSigner resigningSigner() throws JOSEException {
            if (ed25519Key != null) {
                return new Ed25519Signer(ed25519Key);
            } else if (ecKey != null) {
                return ECCryptoSupport.createECDSASigner(ecKey.getPrivate());
            } else {
                throw new IllegalStateException("A signing key is required: signedWith(...) or signedWithEd25519(...)");
            }
        }
    }
}
