package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.artefact;

import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
    void setUp() throws Exception {
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
}
