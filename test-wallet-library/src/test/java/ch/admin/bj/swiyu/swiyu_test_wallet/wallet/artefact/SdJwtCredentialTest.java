package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact;

import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto.Sha256Base64Url;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.KeyPair;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SdJwtCredentialTest {

    private static final String ISSUER_DID = "did:example:issuer";

    private KeyPair issuerKeyPair;
    private ECKey issuerPublicKey;
    private KeyPair holderKeyPair;
    private ECKey holderPublicKey;
    private SdJwtCredential credential;

    @BeforeEach
    void setUp() throws JOSEException {
        issuerKeyPair = ECCryptoSupport.generateECKeyPair();
        issuerPublicKey = ECCryptoSupport.toPublicJwk(issuerKeyPair.getPublic(), ISSUER_DID + "#assert-key-01");
        holderKeyPair = ECCryptoSupport.generateECKeyPair();
        holderPublicKey = ECCryptoSupport.toPublicJwk(holderKeyPair.getPublic(), "holder-key");

        final com.nimbusds.jose.JWSHeader header = new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
                .type(new com.nimbusds.jose.JOSEObjectType("dc+sd-jwt"))
                .keyID(ISSUER_DID + "#assert-key-01")
                .customParam("profile_version", "swiss-profile-vc:1.0.0")
                .build();
        final SignedJWT jwt = new SignedJWT(header, new com.nimbusds.jwt.JWTClaimsSet.Builder()
                .issuer(ISSUER_DID)
                .claim("_sd_alg", "sha-256")
                .claim("_sd", java.util.List.of(
                        Sha256Base64Url.ofUsAscii("WyJhIiwibmFtZSIsIkpvaG4iXQ"),
                        Sha256Base64Url.ofUsAscii("WyJiIiwiY2l0eSIsIkJlcm4iXQ")))
                .claim("vct", "https://example.com/vct")
                .claim("status", Map.of("status_list", Map.of("idx", 1, "uri", "https://example.com/list")))
                .claim("cnf", Map.of("jwk", holderPublicKey.toPublicJWK().toJSONObject()))
                .build());
        jwt.sign(ECCryptoSupport.createECDSASigner(issuerKeyPair.getPrivate()));
        credential = SdJwtCredential.parse(jwt.serialize() + "~WyJhIiwibmFtZSIsIkpvaG4iXQ~WyJiIiwiY2l0eSIsIkJlcm4iXQ~");
    }

    @Test
    void parse_whenACredential_thenSerializeGivesTheSameText() {
        final String text = credential.serialize();

        assertThat(SdJwtCredential.parse(text).serialize())
                .isEqualTo(text);
        assertThat(credential.disclosures())
                .hasSize(2);
        assertThat(credential.keyBindingJwt())
                .isEmpty();
    }

    @Test
    void parse_whenAPresentation_thenSeparatesTheKeyBindingJwt() {
        final String keyBinding = KeyBindingJwt.forPresentation(credential.withoutKeyBinding(), "aud", "n")
                .signedWith(holderKeyPair).build();

        final SdJwtCredential presentation = credential.presentedWith(keyBinding);
        final SdJwtCredential reparsed = SdJwtCredential.parse(presentation.serialize());

        assertThat(reparsed.keyBindingJwt()).contains(keyBinding);
        assertThat(reparsed.disclosures()).isEqualTo(credential.disclosures());
        assertThat(reparsed.withoutKeyBinding()).isEqualTo(credential.withoutKeyBinding());
    }

    @Test
    void parse_whenNoDisclosure_thenKeepsTheTilde() {
        final SdJwtCredential bare = SdJwtCredential.parse(credential.issuerSignedJwt() + "~");

        assertThat(bare.disclosures()).isEmpty();
        assertThat(bare.serialize()).isEqualTo(credential.issuerSignedJwt() + "~");
    }

    @Test
    void withCorruptedIssuerSignature_whenApplied_thenOnlyTheIssuerSignatureStopsVerifying() throws Exception {
        final SdJwtCredential corrupted = credential.withCorruptedIssuerSignature();

        assertThat(SignedJWT.parse(credential.issuerSignedJwt()).verify(new ECDSAVerifier(issuerPublicKey)))
                .isTrue();
        assertThat(SignedJWT.parse(corrupted.issuerSignedJwt()).verify(new ECDSAVerifier(issuerPublicKey)))
                .isFalse();
        assertThat(SignedJWT.parse(corrupted.issuerSignedJwt()).getHeader().toString())
                .isEqualTo(SignedJWT.parse(credential.issuerSignedJwt()).getHeader().toString());
        assertThat(SignedJWT.parse(corrupted.issuerSignedJwt()).getPayload().toString())
                .isEqualTo(SignedJWT.parse(credential.issuerSignedJwt()).getPayload().toString());
        assertThat(corrupted.disclosures())
                .isEqualTo(credential.disclosures());
    }

    @Test
    void withCorruptedKeyBindingSignature_whenApplied_thenOnlyTheKeyBindingSignatureStopsVerifying() throws Exception {
        final String keyBinding = KeyBindingJwt.forPresentation(credential.withoutKeyBinding(), "aud", "n")
                .signedWith(holderKeyPair).build();
        final SdJwtCredential presentation = credential.presentedWith(keyBinding);

        final SdJwtCredential corrupted = presentation.withCorruptedKeyBindingSignature();

        assertThat(SignedJWT.parse(keyBinding).verify(new ECDSAVerifier(holderPublicKey))).isTrue();
        assertThat(SignedJWT.parse(corrupted.keyBindingJwt().orElseThrow()).verify(new ECDSAVerifier(holderPublicKey)))
                .isFalse();
        assertThat(corrupted.issuerSignedJwt()).isEqualTo(presentation.issuerSignedJwt());
        assertThat(corrupted.disclosures()).isEqualTo(presentation.disclosures());
    }

    @Test
    void resign_whenAnotherKeyAndKeyIdAndIssuer_thenTheCredentialIsSignedByThatKeyAndClaimsFollow() throws Exception {
        final KeyPair attackerKeyPair = ECCryptoSupport.generateECKeyPair();
        final ECKey attackerPublicKey = ECCryptoSupport.toPublicJwk(attackerKeyPair.getPublic(), "attacker");

        final SdJwtCredential resigned = credential.resign()
                .signedWith(attackerKeyPair)
                .keyId("did:example:attacker#assert-key-01")
                .issuer(ISSUER_DID)
                .withoutStatus()
                .build();

        final SignedJWT jwt = SignedJWT.parse(resigned.issuerSignedJwt());
        assertThat(jwt.verify(new ECDSAVerifier(attackerPublicKey))).isTrue();
        assertThat(jwt.verify(new ECDSAVerifier(issuerPublicKey))).isFalse();
        assertThat(jwt.getHeader().getKeyID()).isEqualTo("did:example:attacker#assert-key-01");
        assertThat(jwt.getHeader().getType().getType()).isEqualTo("dc+sd-jwt");
        assertThat(jwt.getHeader().getCustomParam("profile_version")).isEqualTo("swiss-profile-vc:1.0.0");
        assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo(ISSUER_DID);
        assertThat(jwt.getJWTClaimsSet().getClaims()).doesNotContainKey("status");
        assertThat(jwt.getJWTClaimsSet().getClaim("vct")).isEqualTo("https://example.com/vct");
        assertThat(resigned.disclosures()).isEqualTo(credential.disclosures());
    }

    @Test
    void resign_whenWithoutIssuer_thenTheIssClaimIsAbsentAndTheRestIsKeptAndSigned() throws Exception {
        final SdJwtCredential resigned = credential.resign().signedWith(issuerKeyPair).withoutIssuer().build();

        final SignedJWT jwt = SignedJWT.parse(resigned.issuerSignedJwt());
        assertThat(jwt.getJWTClaimsSet().getClaims()).as("iss").doesNotContainKey("iss");
        assertThat(jwt.getJWTClaimsSet().getClaim("vct")).as("the other claims are kept").isEqualTo("https://example.com/vct");
        assertThat(jwt.getHeader().getCustomParam("profile_version")).as("the header is kept").isEqualTo("swiss-profile-vc:1.0.0");
        assertThat(jwt.verify(new ECDSAVerifier(issuerPublicKey))).as("signature").isTrue();
        assertThat(resigned.disclosures()).isEqualTo(credential.disclosures());
    }

    @Test
    void resign_whenAnIssuerIsGivenAndDropped_thenFailsInsteadOfPickingOne() {
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> credential.resign().signedWith(issuerKeyPair).issuer("did:example:a").withoutIssuer().build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("contradict");
    }

    @Test
    void resign_whenEd25519_thenTheAlgorithmHeaderIsEd25519() throws Exception {
        final OctetKeyPair edKey = new OctetKeyPairGenerator(com.nimbusds.jose.jwk.Curve.Ed25519).generate();

        final SdJwtCredential resigned = credential.resign().signedWithEd25519(edKey).keyId("did:example:ed#k").build();

        final SignedJWT jwt = SignedJWT.parse(resigned.issuerSignedJwt());
        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("Ed25519");
        assertThat(jwt.verify(new Ed25519Verifier(edKey.toPublicJWK()))).isTrue();
    }

    @Test
    void resign_whenAHolderKeyIsGiven_thenCnfIsReplacedAndTheRestIsKept() throws Exception {
        final OctetKeyPair holderKey = new OctetKeyPairGenerator(com.nimbusds.jose.jwk.Curve.Ed25519).keyID("h").generate();

        final SdJwtCredential resigned = credential.resign().signedWith(issuerKeyPair).holderKey(holderKey).build();

        final SignedJWT jwt = SignedJWT.parse(resigned.issuerSignedJwt());
        assertThat(jwt.verify(new ECDSAVerifier(issuerPublicKey)))
                .as("still signed by the issuer key: only the bound holder key changed")
                .isTrue();
        final Map<?, ?> cnf = (Map<?, ?>) jwt.getJWTClaimsSet().getClaim("cnf");
        assertThat(((Map<?, ?>) cnf.get("jwk")).get("crv")).isEqualTo("Ed25519");
        assertThat(jwt.getHeader().getKeyID()).isEqualTo(ISSUER_DID + "#assert-key-01");
    }

    @Test
    void resign_whenNoSigningKey_thenFails() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> credential.resign().build())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void withTamperedDisclosure_whenApplied_thenOnlyThatValueAndDigestChange() throws Exception {
        final SdJwtCredential tampered = credential.withTamperedDisclosure("name", "Mallory");

        assertThat(decode(tampered.disclosures().get(0)))
                .as("same salt and name, forged value")
                .containsExactly("a", "name", "Mallory");
        assertThat(Sha256Base64Url.ofUsAscii(tampered.disclosures().get(0)))
                .as("the digest the Issuer-signed JWT references no longer matches")
                .isNotEqualTo(Sha256Base64Url.ofUsAscii(credential.disclosures().get(0)));
        assertThat(tampered.disclosures().get(1))
                .isEqualTo(credential.disclosures().get(1));
        assertThat(tampered.issuerSignedJwt())
                .isEqualTo(credential.issuerSignedJwt());
        assertThat(SignedJWT.parse(tampered.issuerSignedJwt()).getJWTClaimsSet().getStringListClaim("_sd"))
                .doesNotContain(Sha256Base64Url.ofUsAscii(tampered.disclosures().getFirst()));
        assertThat(credential.disclosures().getFirst())
                .isEqualTo("WyJhIiwibmFtZSIsIkpvaG4iXQ");
    }

    @Test
    void withTamperedDisclosure_whenTheClaimHasNoDisclosure_thenFails() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> credential.withTamperedDisclosure("unknown", "x"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void withUnreferencedDisclosure_whenApplied_thenAWellFormedDisclosureIsAddedAndTheRestIsKept() throws Exception {
        final SdJwtCredential extended = credential.withUnreferencedDisclosure("name", "Mallory");

        assertThat(extended.disclosures())
                .hasSize(3)
                .startsWith(credential.disclosures().toArray(String[]::new));
        final java.util.List<Object> added = decode(extended.disclosures().get(2));
        assertThat(added)
                .hasSize(3);
        assertThat(added.subList(1, 3))
                .containsExactly("name", "Mallory");
        assertThat((String) added.get(0))
                .as("a fresh salt")
                .isNotBlank()
                .isNotIn("a", "b");
        assertThat(extended.issuerSignedJwt())
                .isEqualTo(credential.issuerSignedJwt());
        assertThat(SignedJWT.parse(extended.issuerSignedJwt()).getJWTClaimsSet().getStringListClaim("_sd"))
                .doesNotContain(Sha256Base64Url.ofUsAscii(extended.disclosures().getLast()));
        assertThat(credential.disclosures())
                .hasSize(2);
    }

    @ParameterizedTest
    @ValueSource(strings = {"exp", "nbf"})
    void resign_whenValidityDateChanges_thenOnlyThatDateChanges(final String claim) throws Exception {
        final java.time.Instant instant = java.time.Instant.parse("2020-01-01T00:00:00Z");
        final SdJwtCredential.Resign resign = credential.resign().signedWith(issuerKeyPair);
        final SdJwtCredential resigned = ("exp".equals(claim) ? resign.expiresAt(instant)
                : resign.notBefore(instant)).build();

        final SignedJWT jwt = SignedJWT.parse(resigned.issuerSignedJwt());
        final var expected = new java.util.LinkedHashMap<>(SignedJWT.parse(credential.issuerSignedJwt())
                .getJWTClaimsSet().getClaims());
        expected.put(claim, java.util.Date.from(instant));
        assertThat(jwt.getJWTClaimsSet().getClaims())
                .isEqualTo(expected);
        assertThat(jwt.verify(new ECDSAVerifier(issuerPublicKey)))
                .isTrue();
        assertThat(resigned.disclosures())
                .isEqualTo(credential.disclosures());
    }

    @Test
    void resign_whenWithStatusIndex_thenOnlyTheIndexChangesAndTheUriIsKept() throws Exception {
        final SdJwtCredential resigned = credential.resign().signedWith(issuerKeyPair).withStatusIndex(999_999).build();

        final SignedJWT jwt = SignedJWT.parse(resigned.issuerSignedJwt());
        final Map<?, ?> statusList = (Map<?, ?>) jwt.getJWTClaimsSet().getJSONObjectClaim("status").get("status_list");
        assertThat(((Number) statusList.get("idx")).intValue())
                .isEqualTo(999_999);
        assertThat(statusList.get("uri"))
                .isEqualTo("https://example.com/list");
        assertThat(jwt.verify(new ECDSAVerifier(issuerPublicKey)))
                .isTrue();
    }



    @SuppressWarnings("unchecked")
    private static java.util.List<Object> decode(final String disclosure) {
        return new com.google.gson.Gson().fromJson(
                new com.nimbusds.jose.util.Base64URL(disclosure).decodeToString(), java.util.List.class);
    }
}
