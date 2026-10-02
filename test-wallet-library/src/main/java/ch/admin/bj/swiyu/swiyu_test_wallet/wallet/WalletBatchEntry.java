package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.gen.verifier.model.DcqlClaimDto;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.credential.HeldCredential;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

@Slf4j
@Getter
@Setter
public class WalletBatchEntry extends WalletEntry {

    private final List<KeyPair> holderKeyPairs = new ArrayList<>();
    private final List<ECKey> holderPublicKeys = new ArrayList<>();
    private final List<JwtProof> proofs = new ArrayList<>();
    private final List<String> issuedCredentials = new ArrayList<>();

    public WalletBatchEntry(Wallet wallet) {
        super(wallet);
    }

    /** The credential at {@code index} with the holder key it is bound to. */
    public HeldCredential heldCredential(final int index) {
        return new HeldCredential(issuedCredentials.get(index), holderKeyPairs.get(index), holderPublicKeys.get(index));
    }

    /** Every credential this issuance produced, each with its holder key. */
    public List<HeldCredential> heldCredentials() {
        return java.util.stream.IntStream.range(0, issuedCredentials.size()).mapToObj(this::heldCredential).toList();
    }

    /** The whole credential, every Disclosure included, followed by a Key Binding JWT (RFC 9901 §4.3). */
    public String createPresentationForSdJwtIndex(final int index, RequestObject requestObject) {
        return heldCredential(index).present(requestObject.getClientId(), requestObject.getNonce());
    }

    /** Only the Disclosures the DCQL query of {@code requestObject} needs, followed by a Key Binding JWT. */
    public String createSelectiveDisclosurePresentationForSdJwtIndex(
            final int index,
            final RequestObject requestObject
    ) {
        return heldCredential(index).present(
                requestObject.getClientId(), requestObject.getNonce(), extractRequestedClaims(requestObject));
    }

    private List<DcqlClaimDto> extractRequestedClaims(RequestObject requestObject) {
        final var dcqlQuery = wallet.resolveVerificationQuery(requestObject);
        if (dcqlQuery.getCredentials() == null || dcqlQuery.getCredentials().isEmpty()) {
            return List.of();
        }

        List<DcqlClaimDto> claims = dcqlQuery.getCredentials().getFirst().getClaims();
        return claims == null ? List.of() : claims;
    }
    public void generateHolderKeys() {
        final int count = getIssuerMetadata().getBatchCredentialIssuance().getBatchSize();
        generateHolderKeys(count);
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
        if (getCredentialOffer() == null) {
            throw new IllegalStateException("Offer or token missing for proof generation");
        }

        proofs.clear();

        for (ECKey pub : holderPublicKeys) {
            final JwtProof proof = new JwtProof(
                    getIssuerMetadata().getCredentialIssuer(),
                    getCNonce(),
                    pub,
                    holderKeyPairs.get(holderPublicKeys.indexOf(pub)),
                    wallet.getMockAttestationAuthority()
            );
            proofs.add(proof);
        }
    }

    public void createProofs(final String uniqueNonce) {
        if (getCredentialOffer() == null) {
            throw new IllegalStateException("Offer or token missing for proof generation");
        }
        proofs.clear();
        for (ECKey pub : holderPublicKeys) {
            var proof = new JwtProof(
                    getIssuerMetadata().getCredentialIssuer(),
                    uniqueNonce,
                    pub,
                    holderKeyPairs.get(holderPublicKeys.indexOf(pub)),
                    wallet.getMockAttestationAuthority()
            );
            proofs.add(proof);
        }
    }

    public List<String> getProofsAsJwt() {
        return proofs.stream().map(JwtProof::toJwt).toList();
    }

    public void setProofsFromJwt(final List<JwtProof> proofs) {
        this.proofs.clear();
        for (JwtProof p : proofs) {
            this.proofs.add(p);
        }
    }

    /** Puts {@code credential} in place of the one at {@code index}, to present something other than what was issued. */
    public void replaceIssuedCredential(final int index, final String credential) {
        issuedCredentials.set(index, credential);
    }

    public void clearIssuedCredentials() {
        issuedCredentials.clear();
    }

    public void addIssuedCredential(String jwt) {
        issuedCredentials.add(jwt);
    }

    public String getVerifiableCredential(final int index) {
        if (issuedCredentials.size() <= index) {
            throw new IndexOutOfBoundsException("index out of bounds for verifiable credential " + index);
        }

        return issuedCredentials.get(index);
    }

    public List<String> getIssuedCredentials() {
        return Collections.unmodifiableList(issuedCredentials);
    }
    
    public WalletBatchEntry duplicate() {
        WalletBatchEntry copy = new WalletBatchEntry(this.getWallet());

        copy.setIssuerVCDeepLink(this.getIssuerVCDeepLink());
        copy.setCredentialOffer(this.getCredentialOffer());
        copy.setIssuerWellKnownConfiguration(this.getIssuerWellKnownConfiguration());
        copy.setIssuerMetadata(this.getIssuerMetadata());
        copy.setToken(this.getToken());
        copy.setCNonce(this.getCNonce());
        copy.setIssuerSdJwt(this.getIssuerSdJwt());
        copy.setTransactionId(this.getTransactionId());

        return copy;
    }

    public void setHolderPublicKeys(final List<ECKey> initialHolderPublicKeys) {
        this.holderPublicKeys.clear();
        for (final ECKey pub : initialHolderPublicKeys) {
            this.holderPublicKeys.add(pub);
        }
    }

    public void setHolderKeyPairs(final List<KeyPair> initialHolderKeyPairs) {
        this.holderKeyPairs.clear();
        for (final KeyPair pair : initialHolderKeyPairs) {
            this.holderKeyPairs.add(pair);
        }
    }

}
