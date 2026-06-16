package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.jwtutil.JwtUtil;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockAttestationAuthority;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.AttestationFactory;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.security.KeyPair;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Date;
import java.util.Optional;

@AllArgsConstructor
@Builder
public class JwtProof {
    private String credentialIssuerURI;
    private String cNonce;
    private ECKey publicJwk;
    private KeyPair keyPair;
    private MockAttestationAuthority attestationAuthority;

    public String toJwt() {
        final ECKey jwk = ECCryptoSupport.toPublicJwk(keyPair.getPublic(), null);

        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(jwk.toPublicJWK());

        if (attestationAuthority != null) {
            final String attestation = AttestationFactory.validHighAttestation(
                    publicJwk,
                    attestationAuthority.getDid(),
                    attestationAuthority.getSigningPrivateKey(),
                    attestationAuthority.getKid()
            );
            headerBuilder.customParam("key_attestation", attestation);
        }

        final JWSHeader header = headerBuilder.build();

        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience(credentialIssuerURI)
                .issueTime(proofIssueTime())
                .claim("nonce", cNonce)
                .build();

        final JWSSigner signer = ECCryptoSupport.createECDSASigner(keyPair.getPrivate());
        final SignedJWT signedJWT = JwtUtil.signJwt(claimsSet, header, signer);

        return signedJWT.serialize();
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

