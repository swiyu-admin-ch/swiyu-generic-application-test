package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

/**
 * What a {@link Wallet} does on the wire, as an immutable value: the protections it applies and the encryption
 * parameters it asks for.
 *
 * <p>The reference specification is OpenID as overridden by the Swiss profiles. {@link #swiss()} is that reference for
 * the flags below. {@link #unprotected()} is what the tests used so far, a wallet without DPoP and without payload
 * encryption; it is a temporary, explicitly named default and not a conformant Swiss-profile wallet. A test that needs the
 * reference or a deliberate deviation declares it ({@link UseWallet}).
 *
 * @param dpop                             sends a DPoP proof on token, credential, and deferred requests
 *                                         (RFC 9449; Swiss issuance profile §3.5, §8.2, §9)
 * @param encryption                       encrypts Credential Requests and asks for an encrypted Credential Response
 *                                         (OID4VCI §10; Swiss issuance profile §8.2) and sends the Authorization Response as
 *                                         {@code direct_post.jwt} when the Verifier asks for it (OID4VP §8.3.1)
 * @param signedMetadataPreferred          asks for signed Credential Issuer Metadata (OID4VCI §12.2.3)
 * @param credentialRequestEncryptionEnc   {@code enc} for the Credential Request, or {@code null} to take the first one the
 *                                         Credential Issuer advertises
 * @param credentialResponseEncryptionEnc  {@code enc} to request for the Credential Response, same rule
 */
public record WalletProfile(
        boolean dpop,
        boolean encryption,
        boolean signedMetadataPreferred,
        String credentialRequestEncryptionEnc,
        String credentialResponseEncryptionEnc
) {

    /** No DPoP, no payload encryption, JSON metadata. Today's default of the tests; see the class comment. */
    public static WalletProfile unprotected() {
        return new WalletProfile(false, false, false, null, null);
    }

    /** DPoP and payload encryption, as the Swiss issuance and verification profiles require. */
    public static WalletProfile swiss() {
        return new WalletProfile(true, true, false, null, null);
    }

    /** The profile a test class declares with {@link UseWallet}, {@link #unprotected()} when it declares none. */
    public static WalletProfile declaredBy(final Class<?> testClass) {
        final UseWallet declared = testClass.getAnnotation(UseWallet.class);
        if (declared == null) {
            return unprotected();
        }
        return unprotected()
                .withDpop(declared.dpop())
                .withEncryption(declared.encryption())
                .withSignedMetadataPreferred(declared.signedMetadata());
    }

    public WalletProfile withDpop(final boolean dpop) {
        return new WalletProfile(dpop, encryption, signedMetadataPreferred, credentialRequestEncryptionEnc, credentialResponseEncryptionEnc);
    }

    public WalletProfile withEncryption(final boolean encryption) {
        return new WalletProfile(dpop, encryption, signedMetadataPreferred, credentialRequestEncryptionEnc, credentialResponseEncryptionEnc);
    }

    public WalletProfile withSignedMetadataPreferred(final boolean signedMetadataPreferred) {
        return new WalletProfile(dpop, encryption, signedMetadataPreferred, credentialRequestEncryptionEnc, credentialResponseEncryptionEnc);
    }

    public WalletProfile withCredentialRequestEncryptionEnc(final String enc) {
        return new WalletProfile(dpop, encryption, signedMetadataPreferred, enc, credentialResponseEncryptionEnc);
    }

    public WalletProfile withCredentialResponseEncryptionEnc(final String enc) {
        return new WalletProfile(dpop, encryption, signedMetadataPreferred, credentialRequestEncryptionEnc, enc);
    }
}
