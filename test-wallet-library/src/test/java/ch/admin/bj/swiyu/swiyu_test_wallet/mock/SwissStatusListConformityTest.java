package ch.admin.bj.swiyu.swiyu_test_wallet.mock;

import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.zip.Deflater;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The v2 update endpoint of the Status Registry mock rejects a Status List Token that is not conformant to the Swiss profile.
 * Each test below builds a conformant token and breaks exactly one requirement, so a failing test names the requirement.
 *
 * <p>Specification: {@code updateStatusListEntry} (v2) of {@code SWIYU_Core_Business_status.yaml} of the Credential Issuer
 * (header {@code typ} and {@code profile_version}, {@code exp}, decompressed {@code lst} of at most 200 KB), and Token
 * Status List draft 20 §4.1 ({@code lst} is a ZLIB stream in base64url) and §4.2 ({@code bits} is 1, 2, 4 or 8).
 */
class SwissStatusListConformityTest {

    private static final KeyPair KEY_PAIR = newKeyPair();

    private static KeyPair newKeyPair() {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A Status List Token as the Credential Issuer publishes it, every requirement met. */
    private static TokenBuilder conformantToken() {
        return new TokenBuilder();
    }

    private static final class TokenBuilder {
        private String type = "statuslist+jwt";
        private String profileVersion = "swiss-profile-vc:1.0.0";
        private Date expiration = new Date(System.currentTimeMillis() + 3_600_000L);
        private Object bits = 2;
        private Object lst = zlibBase64Url(new byte[16]);

        TokenBuilder withType(final String type) {
            this.type = type;
            return this;
        }

        TokenBuilder withProfileVersion(final String profileVersion) {
            this.profileVersion = profileVersion;
            return this;
        }

        TokenBuilder withoutExpiration() {
            this.expiration = null;
            return this;
        }

        TokenBuilder withBits(final Object bits) {
            this.bits = bits;
            return this;
        }

        TokenBuilder withLst(final Object lst) {
            this.lst = lst;
            return this;
        }

        String build() {
            try {
                final JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("k");
                if (type != null) {
                    header.type(new JOSEObjectType(type));
                }
                if (profileVersion != null) {
                    header.customParam("profile_version", profileVersion);
                }
                final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                        .subject("https://mockserver:1080/api/v1/statuslist/x.jwt")
                        .claim("status_list", Map.of("bits", bits, "lst", lst));
                if (expiration != null) {
                    claims.expirationTime(expiration);
                }
                final SignedJWT jwt = new SignedJWT(header.build(), claims.build());
                jwt.sign(ECCryptoSupport.createECDSASigner(KEY_PAIR.getPrivate()));
                return jwt.serialize();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private static String zlibBase64Url(final byte[] data) {
        final Deflater deflater = new Deflater();
        deflater.setInput(data);
        deflater.finish();
        final byte[] buffer = new byte[data.length + 64];
        final int length = deflater.deflate(buffer);
        deflater.end();
        final byte[] compressed = new byte[length];
        System.arraycopy(buffer, 0, compressed, 0, length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(compressed);
    }

    @Test
    void violations_whenTheTokenMeetsEveryRequirement_thenThereAreNone() {
        assertThat(SwissStatusListConformity.violations(conformantToken().build())).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 4, 8})
    void violations_whenBitsIsAnAllowedValue_thenThereAreNone(final int bits) {
        assertThat(SwissStatusListConformity.violations(conformantToken().withBits(bits).build())).isEmpty();
    }

    @Test
    void violations_whenTypIsNotStatuslistJwt_thenOnlyTypIsReported() {
        assertThat(SwissStatusListConformity.violations(conformantToken().withType("JWT").build()))
                .singleElement().asString().contains("'typ'");
    }

    @Test
    void violations_whenTypIsMissing_thenOnlyTypIsReported() {
        assertThat(SwissStatusListConformity.violations(conformantToken().withType(null).build()))
                .singleElement().asString().contains("'typ'");
    }

    @Test
    void violations_whenProfileVersionIsMissing_thenOnlyProfileVersionIsReported() {
        assertThat(SwissStatusListConformity.violations(conformantToken().withProfileVersion(null).build()))
                .singleElement().asString().contains("'profile_version'");
    }

    @Test
    void violations_whenProfileVersionIsAnotherVersion_thenOnlyProfileVersionIsReported() {
        assertThat(SwissStatusListConformity.violations(conformantToken().withProfileVersion("swiss-profile-vc:2.0.0").build()))
                .singleElement().asString().contains("'profile_version'");
    }

    @Test
    void violations_whenExpIsMissing_thenOnlyExpIsReported() {
        assertThat(SwissStatusListConformity.violations(conformantToken().withoutExpiration().build()))
                .singleElement().asString().contains("'exp'");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 3, 16})
    void violations_whenBitsIsNotOneTwoFourOrEight_thenOnlyBitsIsReported(final int bits) {
        assertThat(SwissStatusListConformity.violations(conformantToken().withBits(bits).build()))
                .singleElement().asString().contains("'bits'");
    }

    @Test
    void violations_whenBitsIsAString_thenTheStatusListClaimIsReported() {
        assertThat(SwissStatusListConformity.violations(conformantToken().withBits("2").build()))
                .singleElement().asString().contains("integer 'bits'");
    }

    @Test
    void violations_whenLstIsNotBase64Url_thenOnlyLstIsReported() {
        assertThat(SwissStatusListConformity.violations(conformantToken().withLst("not base64url!").build()))
                .singleElement().asString().contains("base64url");
    }

    @Test
    void violations_whenLstIsNotAZlibStream_thenOnlyLstIsReported() {
        final String notZlib = Base64.getUrlEncoder().withoutPadding().encodeToString("plain text".getBytes());

        assertThat(SwissStatusListConformity.violations(conformantToken().withLst(notZlib).build()))
                .singleElement().asString().contains("ZLIB");
    }

    @Test
    void violations_whenLstDecompressesToExactlyTheLimit_thenThereAreNone() {
        final String lst = zlibBase64Url(new byte[SwissStatusListConformity.MAX_DECOMPRESSED_BYTES]);

        assertThat(SwissStatusListConformity.violations(conformantToken().withLst(lst).build())).isEmpty();
    }

    @Test
    void violations_whenLstDecompressesToOneByteOverTheLimit_thenOnlyTheSizeIsReported() {
        final String lst = zlibBase64Url(new byte[SwissStatusListConformity.MAX_DECOMPRESSED_BYTES + 1]);

        assertThat(SwissStatusListConformity.violations(conformantToken().withLst(lst).build()))
                .singleElement().asString().contains("200 KB");
    }

    @Test
    void violations_whenSeveralRequirementsAreBroken_thenEachOneIsReported() {
        assertThat(SwissStatusListConformity.violations(
                conformantToken().withType("JWT").withProfileVersion(null).withoutExpiration().build()))
                .hasSize(3);
    }

    @Test
    void violations_whenTheBodyIsNotAJwt_thenItIsReportedInsteadOfThrowing() {
        assertThat(SwissStatusListConformity.violations("not a jwt")).singleElement().asString().contains("signed JWT");
        assertThat(SwissStatusListConformity.violations(null)).singleElement().asString().contains("signed JWT");
    }
}
