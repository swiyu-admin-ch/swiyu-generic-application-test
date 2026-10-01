package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.credential;

import ch.admin.bj.swiyu.gen.verifier.model.DcqlClaimDto;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact.KeyBindingJwt;
import com.nimbusds.jose.jwk.ECKey;

import java.security.KeyPair;
import java.util.List;

/**
 * A Verifiable Credential the Wallet holds: the SD-JWT VC the Credential Issuer issued and the holder key it is bound to
 * ({@code cnf.jwk}, RFC 9901 §4.1.2). It knows how to present itself to a Verifier.
 *
 * @param sdJwt           {@code <Issuer-signed JWT>~<D1>~...~<DN>~}, as issued
 * @param holderKey       the private key of the key the credential is bound to
 * @param holderPublicKey its public key
 */
public record HeldCredential(String sdJwt, KeyPair holderKey, ECKey holderPublicKey) {

    /**
     * The whole credential, every Disclosure included, followed by a Key Binding JWT (RFC 9901 §4.3).
     *
     * @param audience the full Client Identifier of the Verifier (OID4VP Appendix B.3.6, §14.8)
     * @param nonce    the nonce of the Authorization Request
     */
    public String present(final String audience, final String nonce) {
        return sdJwt + KeyBindingJwt.forPresentation(sdJwt, audience, nonce).signedWith(holderKey).build();
    }

    /** Only the Disclosures needed for {@code requestedClaims} (see {@link DisclosureSelector}), then a Key Binding JWT. */
    public String present(final String audience, final String nonce, final List<DcqlClaimDto> requestedClaims) {
        try {
            final String selected = DisclosureSelector.select(sdJwt, requestedClaims);
            return selected + KeyBindingJwt.forPresentation(selected, audience, nonce).signedWith(holderKey).build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create selective disclosure presentation", e);
        }
    }
}
