package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

class WalletProfileTest {

    @UseWallet(dpop = true, encryption = true, signedMetadata = true)
    private static final class DeclaresEverything {
    }

    @UseWallet(dpop = true)
    private static final class DeclaresDpopOnly {
    }

    private static final class DeclaresNothing {
    }

    @Test
    void unprotected_whenCreated_thenUsesNeitherDpopNorEncryption() {
        final WalletProfile profile = WalletProfile.unprotected();

        assertThat(profile.dpop()).isFalse();
        assertThat(profile.encryption()).isFalse();
        assertThat(profile.signedMetadataPreferred()).isFalse();
        assertThat(profile.credentialRequestEncryptionEnc()).isNull();
        assertThat(profile.credentialResponseEncryptionEnc()).isNull();
    }

    @Test
    void swiss_whenCreated_thenUsesDpopAndEncryption() {
        final WalletProfile profile = WalletProfile.swiss();

        assertThat(profile.dpop()).isTrue();
        assertThat(profile.encryption()).isTrue();
    }

    @Test
    void with_whenChangingOneSetting_thenReturnsANewProfileAndLeavesTheOriginalUntouched() {
        final WalletProfile original = WalletProfile.unprotected();

        final WalletProfile changed = original.withDpop(true).withCredentialResponseEncryptionEnc("A128GCM");

        assertThat(original).isEqualTo(WalletProfile.unprotected());
        assertThat(changed.dpop()).isTrue();
        assertThat(changed.credentialResponseEncryptionEnc()).isEqualTo("A128GCM");
        assertThat(changed.encryption()).isFalse();
    }

    @Test
    void declaredBy_whenTheClassDeclaresASettings_thenAppliesOnlyThose() {
        assertThat(WalletProfile.declaredBy(DeclaresDpopOnly.class))
                .isEqualTo(WalletProfile.unprotected().withDpop(true));
        assertThat(WalletProfile.declaredBy(DeclaresEverything.class))
                .isEqualTo(WalletProfile.swiss().withSignedMetadataPreferred(true));
    }

    @Test
    void declaredBy_whenTheClassDeclaresNothing_thenIsUnprotected() {
        assertThat(WalletProfile.declaredBy(DeclaresNothing.class))
                .isEqualTo(WalletProfile.unprotected());
    }

    @Test
    void wallet_whenItsSettersAreUsed_thenTheProfileFollows() {
        final Wallet wallet = new Wallet(RestClient.create(), null, null);

        wallet.setUseDPoP(true);
        wallet.setUseEncryption(true);
        wallet.setCredentialRequestEncryptionEnc("A256GCM");

        assertThat(wallet.getProfile())
                .isEqualTo(WalletProfile.swiss().withCredentialRequestEncryptionEnc("A256GCM"));
        assertThat(wallet.isUseDPoP()).isTrue();
        assertThat(wallet.getCredentialRequestEncryptionEnc()).isEqualTo("A256GCM");
    }

    @Test
    void wallet_whenCreated_thenStartsUnprotected() {
        assertThat(new Wallet(RestClient.create(), null, null).getProfile())
                .isEqualTo(WalletProfile.unprotected());
    }
}
