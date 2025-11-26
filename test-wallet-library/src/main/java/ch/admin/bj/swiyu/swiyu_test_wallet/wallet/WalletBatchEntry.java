package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import lombok.Getter;
import lombok.Setter;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Getter
@Setter
public class WalletBatchEntry extends WalletEntry {

    private final List<KeyPair> holderKeyPairs = new ArrayList<>();
    private final List<ECKey> holderPublicKeys = new ArrayList<>();
    private final List<JwtProof> proofs = new ArrayList<>();
    private final List<String> issuedCredentials = new ArrayList<>();
    private String currentNonce;

    public WalletBatchEntry(Wallet wallet) {
        super(wallet);
    }

    public void generateHolderKeys(int count) {
        holderKeyPairs.clear();
        holderPublicKeys.clear();

        for (int i = 0; i < count; i++) {
            var pair = ECCryptoSupport.generateECKeyPair();
            var ec = new ECKey.Builder(Curve.P_256, (java.security.interfaces.ECPublicKey) pair.getPublic())
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID("holder-key-" + UUID.randomUUID())
                    .build();
            holderKeyPairs.add(pair);
            holderPublicKeys.add(ec);
        }
    }

    public void createProofs() {
        if (getCredentialOffer() == null || getToken() == null) {
            throw new IllegalStateException("Offer or token missing for proof generation");
        }

        proofs.clear();

        for (ECKey pub : holderPublicKeys) {
            String uniqueNonce = currentNonce != null ?
                    currentNonce + "-" + UUID.randomUUID().toString() :
                    getToken().getcNonce();

            var proof = new JwtProof(
                    getCredentialOffer().getCredentialIssuerUriAsString(),
                    uniqueNonce,
                    pub,
                    holderKeyPairs.get(holderPublicKeys.indexOf(pub))
            );
            proofs.add(proof);
        }
    }

    public List<String> getProofsAsJwt() {
        return proofs.stream().map(JwtProof::toJwt).toList();
    }

    public void addIssuedCredential(String jwt) {
        issuedCredentials.add(jwt);
    }
}

