package ch.admin.bj.swiyu.swiyu_test_wallet.fixture;

import ch.admin.bj.swiyu.swiyu_test_wallet.identity.KeyUtil;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class StatusListTokenFixtureTest {

    @Test
    void statusList_whenLifetimeChanges_thenSignatureAndStatusIdentityRemainValid() throws Exception {
        // Given
        final var keyPair = ECCryptoSupport.generateECKeyPair();
        final var key = KeyUtil.createJWKFromKeyPair(keyPair).toECKey();
        final String uri = "https://registry.example/status/one.jwt";
        final var status = Map.of("bits", 2, "lst", "eNoDAAAAAAE");
        final var original = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("statuslist+jwt")).keyID("did:example:issuer#key-1").build(),
                new JWTClaimsSet.Builder().issuer("did:example:issuer").subject(uri)
                        .issueTime(Date.from(Instant.parse("2026-01-01T00:00:00Z")))
                        .claim("status_list", status).build());
        original.sign(new ECDSASigner(key));
        final Instant expiresAt = Instant.parse("2026-01-01T00:00:08Z");

        // When
        final var actual = SignedJWT.parse(StatusListTokenFixture.withLifetime(original.serialize(), keyPair, expiresAt, 120));

        // Then
        assertThat(actual.verify(new ECDSAVerifier(key.toPublicJWK())))
                .as("Changing cache boundaries must not accidentally create an invalid-signature scenario")
                .isTrue();
        assertThat(actual.getHeader().getKeyID())
                .isEqualTo(original.getHeader().getKeyID());
        assertThat(actual.getHeader().getType())
                .isEqualTo(new JOSEObjectType("statuslist+jwt"));
        assertThat(actual.getJWTClaimsSet().getSubject())
                .isEqualTo(uri);
        assertThat(actual.getJWTClaimsSet().getIssuer())
                .isEqualTo(original.getJWTClaimsSet().getIssuer());
        assertThat(actual.getJWTClaimsSet().getJSONObjectClaim("status_list"))
                .isEqualTo(SignedJWT.parse(original.serialize()).getJWTClaimsSet().getJSONObjectClaim("status_list"));
        assertThat(actual.getJWTClaimsSet().getExpirationTime().toInstant())
                .isEqualTo(expiresAt);
        assertThat(actual.getJWTClaimsSet().getLongClaim("ttl"))
                .isEqualTo(120L);
    }
}
