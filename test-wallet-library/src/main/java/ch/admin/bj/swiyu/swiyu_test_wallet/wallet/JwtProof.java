package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.jwtutil.JwtUtil;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.security.KeyPair;
import java.util.Date;

@AllArgsConstructor
@Builder
public class JwtProof {
    private String credentialIssuerURI;
    private String cNonce;
    private ECKey publicJwk;
    private KeyPair keyPair;

    public String toJwt() {
        final ECKey jwk = ECCryptoSupport.toPublicJwk(keyPair.getPublic(), null);
        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(jwk.toPublicJWK())
                .build();
        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience(credentialIssuerURI)
                .issueTime(new Date())
                .claim("nonce", cNonce)
                .build();
        final JWSSigner signer = ECCryptoSupport.createECDSASigner(keyPair.getPrivate());
        final SignedJWT signedJWT = JwtUtil.signJwt(claimsSet, header, signer);

        return signedJWT.serialize();
    }
}
