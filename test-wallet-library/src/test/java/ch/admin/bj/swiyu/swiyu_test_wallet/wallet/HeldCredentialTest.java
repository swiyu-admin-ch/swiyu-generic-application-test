package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.credential.HeldCredential;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

class HeldCredentialTest {

    private WalletBatchEntry entry;
    private TestSdJwtVc issued;

    @BeforeEach
    void setUp() {
        entry = new WalletBatchEntry(new Wallet(RestClient.create(), null, null));
        entry.generateHolderKeys(2);
        issued = TestSdJwtVc.issueFor(entry.getHolderPublicKeys().get(1));
        entry.addIssuedCredential(TestSdJwtVc.issueFor(entry.getHolderPublicKeys().get(0)).serialized());
        entry.addIssuedCredential(issued.serialized());
    }

    @Test
    void heldCredentials_whenABatchWasIssued_thenEachCredentialIsPairedWithItsOwnHolderKey() {
        assertThat(entry.heldCredentials())
                .hasSize(2);
        final HeldCredential second = entry.heldCredential(1);
        assertThat(second.sdJwt())
                .isEqualTo(issued.serialized());
        assertThat(second.holderPublicKey())
                .isEqualTo(entry.getHolderPublicKeys().get(1));
        assertThat(second.holderKey())
                .isEqualTo(entry.getHolderKeyPairs().get(1));
    }

    @Test
    void present_whenCalled_thenTheKeyBindingJwtIsSignedWithThatCredentialsKey() throws Exception {
        final HeldCredential second = entry.heldCredential(1);

        final String presentation = second.present("decentralized_identifier:did:tdw:example:verifier", "nonce-1");

        assertThat(presentation)
                .startsWith(issued.serialized());
        final SignedJWT keyBinding = SignedJWT.parse(presentation.substring(issued.serialized().length()));
        assertThat(keyBinding.verify(new com.nimbusds.jose.crypto.ECDSAVerifier(second.holderPublicKey())))
                .isTrue();
    }
}
