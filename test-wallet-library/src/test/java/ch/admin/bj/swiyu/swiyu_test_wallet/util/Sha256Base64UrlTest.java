package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import ch.admin.bj.swiyu.dpop.DpopHashUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The expected values are the well-known SHA-256 test vectors (FIPS 180-4), base64url encoded without padding: the empty
 * string and "abc". They do not come from the implementation under test or from the library.
 */
class Sha256Base64UrlTest {

    @Test
    void ofUsAscii_whenEmptyText_thenIsTheKnownSha256OfTheEmptyString() {
        assertThat(Sha256Base64Url.ofUsAscii(""))
                .isEqualTo("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
    }

    @Test
    void ofUsAscii_whenAbc_thenIsTheKnownSha256OfAbc() {
        assertThat(Sha256Base64Url.ofUsAscii("abc"))
                .isEqualTo("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
    }

    @Test
    void ofUsAscii_whenAnAccessToken_thenAgreesWithTheLibraryHelperTheCredentialIssuerUses() {
        final String accessToken = "7e3d56f6-cfc0-4d33-98ad-7147a64f8296";

        assertThat(Sha256Base64Url.ofUsAscii(accessToken))
                .isEqualTo(DpopHashUtil.sha256(accessToken));
    }

    @Test
    void ofUsAscii_whenATildeTerminatedSdJwt_thenCoversTheTrailingTilde() {
        assertThat(Sha256Base64Url.ofUsAscii("a.b.c~d~"))
                .as("RFC 9901 §4.3.1: the hash covers everything up to and including the last tilde")
                .isNotEqualTo(Sha256Base64Url.ofUsAscii("a.b.c~d"));
    }
}
