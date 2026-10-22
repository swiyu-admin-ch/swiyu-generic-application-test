package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.jwtutil.JwtUtil;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockAttestationAuthority;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto.AttestationFactory;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.Builder;

import java.security.KeyPair;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Date;
import java.util.Optional;

public class JwtProof {
    private static final int NONCE_TIMESTAMP_PART_INDEX = 1;
    private final String credentialIssuerURI;
    private final String cNonce;
    private final ECKey publicJwk;
    private final KeyPair keyPair;
    private final MockAttestationAuthority attestationAuthority;
    private final OctetKeyPair ed25519KeyPair;
    private final Instant issuedAt;
    private final String keyAttestation;

    public JwtProof(
            final String credentialIssuerURI,
            final String cNonce,
            final ECKey publicJwk,
            final KeyPair keyPair,
            final MockAttestationAuthority attestationAuthority
    ) {
        this(credentialIssuerURI, cNonce, publicJwk, keyPair, attestationAuthority, null, null);
    }

    @Builder
    public JwtProof(
            final String credentialIssuerURI,
            final String cNonce,
            final ECKey publicJwk,
            final KeyPair keyPair,
            final MockAttestationAuthority attestationAuthority,
            final Instant issuedAt,
            final String keyAttestation
    ) {
        this.credentialIssuerURI = credentialIssuerURI;
        this.cNonce = cNonce;
        this.publicJwk = publicJwk;
        this.keyPair = keyPair;
        this.attestationAuthority = attestationAuthority;
        this.ed25519KeyPair = null;
        this.issuedAt = issuedAt;
        this.keyAttestation = keyAttestation;
    }

    private JwtProof(
            final String credentialIssuerURI,
            final String cNonce,
            final OctetKeyPair ed25519KeyPair
    ) {
        this.credentialIssuerURI = credentialIssuerURI;
        this.cNonce = cNonce;
        this.publicJwk = null;
        this.keyPair = null;
        this.attestationAuthority = null;
        this.ed25519KeyPair = ed25519KeyPair;
        this.issuedAt = null;
        this.keyAttestation = null;
    }

    public static JwtProof ed25519(
            final String credentialIssuerURI,
            final String cNonce,
            final OctetKeyPair keyPair
    ) {
        return new JwtProof(credentialIssuerURI, cNonce, keyPair);
    }

    public String toJwt() {
        try {
            final JWSHeader.Builder headerBuilder;
            final JWSSigner signer;

            if (ed25519KeyPair != null) {
                headerBuilder = new JWSHeader.Builder(JWSAlgorithm.Ed25519)
                        .jwk(ed25519KeyPair.toPublicJWK());
                signer = new Ed25519Signer(ed25519KeyPair);
            } else {
                final ECKey jwk = ECCryptoSupport.toPublicJwk(keyPair.getPublic(), null);
                headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .jwk(jwk.toPublicJWK());
                signer = ECCryptoSupport.createECDSASigner(keyPair.getPrivate());

                if (keyAttestation != null) {
                    headerBuilder.customParam("key_attestation", keyAttestation);
                } else if (attestationAuthority != null) {
                    final String attestation = AttestationFactory.validHighAttestation(
                            publicJwk,
                            attestationAuthority.getIssuerClaim(),
                            attestationAuthority.getSigningPrivateKey(),
                            attestationAuthority.getKid()
                    );
                    headerBuilder.customParam("key_attestation", attestation);
                }
            }

            final JWSHeader header = headerBuilder
                    .type(new JOSEObjectType("openid4vci-proof+jwt"))
                    .build();
            final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .audience(credentialIssuerURI)
                    .issueTime(proofIssueTime())
                    .claim("nonce", cNonce)
                    .build();
            final SignedJWT signedJWT = JwtUtil.signJwt(claimsSet, header, signer);

            return signedJWT.serialize();
        } catch (JOSEException exception) {
            throw new IllegalStateException("Failed to create holder binding Proof JWT", exception);
        }
    }

    private Date proofIssueTime() {
        if (issuedAt != null) {
            return Date.from(issuedAt);
        }
        return nonceInstant()
                .map(Date::from)
                .orElseGet(Date::new);
    }

    /** Named deviations for negative tests; the default builder keeps the wallet's existing behavior. */
    public static class JwtProofBuilder {
        /** Uses the audience of another Credential Issuer (OID4VCI Appendix F.1). */
        public JwtProofBuilder withAudience(final String audience) {
            return credentialIssuerURI(audience);
        }

        /** Uses a nonce other than the server-provided c_nonce (OID4VCI Appendix F.1). */
        public JwtProofBuilder withNonce(final String nonce) {
            return cNonce(nonce);
        }

        /** Omits the nonce despite the Credential Issuer's Nonce Endpoint (OID4VCI Appendix F.1). */
        public JwtProofBuilder withoutNonce() {
            return cNonce(null);
        }

        /** Overrides iat to exercise the Credential Issuer's freshness policy (OID4VCI Appendix F.4). */
        public JwtProofBuilder withIssuedAt(final Instant instant) {
            return issuedAt(instant);
        }
    }

    private Optional<Instant> nonceInstant() {
        if (cNonce == null) {
            return Optional.empty();
        }

        final String[] parts = cNonce.split("::", -1);
        if (parts.length <= NONCE_TIMESTAMP_PART_INDEX) {
            return Optional.empty();
        }

        try {
            return Optional.of(Instant.parse(parts[NONCE_TIMESTAMP_PART_INDEX]));
        } catch (DateTimeParseException ex) {
            return Optional.empty();
        }
    }
}
