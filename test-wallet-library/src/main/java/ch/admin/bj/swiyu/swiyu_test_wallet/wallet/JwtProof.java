package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.jwtutil.JwtUtil;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockAttestationAuthority;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.AttestationFactory;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
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
    private final String credentialIssuerURI;
    private final String cNonce;
    private final ECKey publicJwk;
    private final KeyPair keyPair;
    private final MockAttestationAuthority attestationAuthority;
    private final OctetKeyPair ed25519KeyPair;

    @Builder
    public JwtProof(
            final String credentialIssuerURI,
            final String cNonce,
            final ECKey publicJwk,
            final KeyPair keyPair,
            final MockAttestationAuthority attestationAuthority
    ) {
        this.credentialIssuerURI = credentialIssuerURI;
        this.cNonce = cNonce;
        this.publicJwk = publicJwk;
        this.keyPair = keyPair;
        this.attestationAuthority = attestationAuthority;
        this.ed25519KeyPair = null;
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

                if (attestationAuthority != null) {
                    final String attestation = AttestationFactory.validHighAttestation(
                            publicJwk,
                            attestationAuthority.getDid(),
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
        return nonceInstant()
                .map(Date::from)
                .orElseGet(Date::new);
    }

    private Optional<Instant> nonceInstant() {
        if (cNonce == null) {
            return Optional.empty();
        }

        final String[] parts = cNonce.split("::", -1);
        if (parts.length < 2) {
            return Optional.empty();
        }

        try {
            return Optional.of(Instant.parse(parts[1]));
        } catch (DateTimeParseException ex) {
            return Optional.empty();
        }
    }
}
