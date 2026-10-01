package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto;

import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact.DpopProof;
import com.nimbusds.jose.jwk.ECKey;
import lombok.experimental.UtilityClass;

import java.security.KeyPair;

/** Conformant DPoP proofs for the requests the Wallet sends. For a deliberate deviation use {@link DpopProof}. */
@UtilityClass
public class DPoPSupport {

    public static String createDpopProofForToken(
            String uri,
            String nonce,
            KeyPair dpopKeyPair,
            ECKey dpopPublicJwk
    ) {
        return createDpopProofForToken(uri, nonce, dpopKeyPair, dpopPublicJwk, null);
    }

    public static String createDpopProofForToken(
            String uri,
            String nonce,
            KeyPair dpopKeyPair,
            ECKey dpopPublicJwk,
            String token
    ) {
        return DpopProof.forRequest("POST", uri)
                .nonce(nonce)
                .accessToken(token)
                .signedWith(dpopKeyPair, dpopPublicJwk)
                .build();
    }
}
