package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
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
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .keyID(ECCryptoSupport.createDidJwkKey(keyPair.getPublic(), "wallet-proof-key-1"))
                .build();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience(credentialIssuerURI)
                .issueTime(new Date())
                .claim("nonce", cNonce)
                .build();

        var signedJWT = new SignedJWT(header, claimsSet);
        try {
            signedJWT.sign(ECCryptoSupport.createECDSASigner(keyPair.getPrivate()));
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }

        return signedJWT.serialize();
    }
}
