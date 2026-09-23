package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.gen.verifier.model.DcqlCredentialDto;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlQueryDto;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerifierInfoEntryDto;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.TrustConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.TestSupportException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VerificationQueryResolverTest {

    private static final Instant NOW = Instant.parse("2026-09-01T12:00:00Z");
    private static final String TRUST_KEY_ID = "did:example:trust#assert-key-01";
    private static final String VERIFIER_DID = "did:example:verifier";
    private static final String CLIENT_ID = "decentralized_identifier:" + VERIFIER_DID;
    private static final String SCOPE = "ch.swiyu.test.presentation";
    private static final String QUERY_ID = "university_credential";

    private VerificationQueryResolver resolver;
    private KeyPair trustKeyPair;
    private TrustConfig trustConfig;

    @BeforeEach
    void setUp() {
        resolver = new VerificationQueryResolver(Clock.fixed(NOW, ZoneOffset.UTC));
        trustKeyPair = generateEcKeyPair();
        final JWK trustJwk = KeyUtil.createJWKFromKeyPair(trustKeyPair);
        trustConfig = TrustConfig.builder()
                .trustAssertKeyId(TRUST_KEY_ID)
                .trustAssertPublicJwk(trustJwk.toPublicJWK().toJSONString())
                .build();
    }

    @Test
    void directDcqlQuery_whenPresent_thenDoesNotRequireVqPs() {
        final DcqlQueryDto directQuery = new DcqlQueryDto()
                .addCredentialsItem(new DcqlCredentialDto().id(QUERY_ID));

        final DcqlQueryDto resolvedQuery = resolver.resolve(
                new RequestObject().dcqlQuery(directQuery),
                null
        );

        assertThat(resolvedQuery)
                .isSameAs(directQuery);
    }

    @Test
    void validVqPs_whenTrustedAndBoundToRequest_thenReturnsEmbeddedDcqlQuery() throws JOSEException {
        final RequestObject requestObject = requestObject(
                signedVqPs(trustKeyPair, TRUST_KEY_ID, VERIFIER_DID, SCOPE, NOW.minusSeconds(60), NOW.plusSeconds(60)),
                SCOPE
        );

        final DcqlQueryDto resolvedQuery = resolver.resolve(requestObject, trustConfig);

        assertThat(resolvedQuery.getCredentials())
                .singleElement()
                .satisfies(credential -> {
                    assertThat(credential.getId())
                            .isEqualTo(QUERY_ID);
                    assertThat(credential.getFormat())
                            .isEqualTo("dc+sd-jwt");
                    assertThat(credential.getMeta().getVctValues())
                            .containsExactly("https://example.com/vct");
                });
    }

    @Test
    void vqPs_whenSignatureDoesNotMatchTrustAnchor_thenFailsClosed() throws JOSEException {
        final KeyPair attackerKeyPair = generateEcKeyPair();
        final RequestObject requestObject = requestObject(
                signedVqPs(attackerKeyPair, TRUST_KEY_ID, VERIFIER_DID, SCOPE, NOW.minusSeconds(60), NOW.plusSeconds(60)),
                SCOPE
        );

        assertThatThrownBy(() -> resolver.resolve(requestObject, trustConfig))
                .isInstanceOf(TestSupportException.class)
                .hasMessage("vqPS signature is invalid");
    }

    @Test
    void verifierInfo_whenMultipleVqPsArePresent_thenFailsClosed() throws JOSEException {
        final String vqPs = signedVqPs(
                trustKeyPair,
                TRUST_KEY_ID,
                VERIFIER_DID,
                SCOPE,
                NOW.minusSeconds(60),
                NOW.plusSeconds(60)
        );
        final RequestObject requestObject = requestObject(vqPs, SCOPE)
                .verifierInfo(List.of(verifierInfo(vqPs), verifierInfo(vqPs)));

        assertThatThrownBy(() -> resolver.resolve(requestObject, trustConfig))
                .isInstanceOf(TestSupportException.class)
                .hasMessage("verifier_info must contain exactly one vqPS");
    }

    @Test
    void vqPs_whenVerifierInfoFormatIsNotJwt_thenFailsClosed() throws JOSEException {
        final String vqPs = signedVqPs(
                trustKeyPair,
                TRUST_KEY_ID,
                VERIFIER_DID,
                SCOPE,
                NOW.minusSeconds(60),
                NOW.plusSeconds(60)
        );
        final RequestObject requestObject = requestObject(vqPs, SCOPE)
                .verifierInfo(List.of(verifierInfo(vqPs).format("json")));

        assertThatThrownBy(() -> resolver.resolve(requestObject, trustConfig))
                .isInstanceOf(TestSupportException.class)
                .hasMessage("vqPS verifier_info format must be jwt");
    }

    @Test
    void vqPs_whenScopeDoesNotMatchAuthorizationRequest_thenFailsClosed() throws JOSEException {
        final RequestObject requestObject = requestObject(
                signedVqPs(trustKeyPair, TRUST_KEY_ID, VERIFIER_DID, SCOPE, NOW.minusSeconds(60), NOW.plusSeconds(60)),
                "ch.swiyu.other.presentation"
        );

        assertThatThrownBy(() -> resolver.resolve(requestObject, trustConfig))
                .isInstanceOf(TestSupportException.class)
                .hasMessage("Authorization Request scope must match the vqPS request.scope");
    }

    @Test
    void vqPs_whenExpired_thenFailsClosed() throws JOSEException {
        final RequestObject requestObject = requestObject(
                signedVqPs(trustKeyPair, TRUST_KEY_ID, VERIFIER_DID, SCOPE, NOW.minusSeconds(120), NOW.minusSeconds(1)),
                SCOPE
        );

        assertThatThrownBy(() -> resolver.resolve(requestObject, trustConfig))
                .isInstanceOf(TestSupportException.class)
                .hasMessage("vqPS is expired or has no exp");
    }

    private RequestObject requestObject(final String vqPs, final String scope) {
        return new RequestObject()
                .clientId(CLIENT_ID)
                .scope(scope)
                .verifierInfo(List.of(verifierInfo(vqPs)));
    }

    private VerifierInfoEntryDto verifierInfo(final String vqPs) {
        return new VerifierInfoEntryDto()
                .format("jwt")
                .data(vqPs);
    }

    private String signedVqPs(
            final KeyPair signingKeyPair,
            final String keyId,
            final String subject,
            final String scope,
            final Instant issuedAt,
            final Instant expiresAt
    ) throws JOSEException {
        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(keyId)
                .type(new JOSEObjectType(VerificationQueryResolver.VQPS_TYPE))
                .customParam("profile_version", VerificationQueryResolver.TP2_PROFILE_VERSION)
                .build();
        final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(subject)
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(expiresAt))
                .claim("request", Map.of(
                        "type", "DCQL",
                        "scope", scope,
                        "query", Map.of(
                                "credentials", List.of(Map.of(
                                        "id", QUERY_ID,
                                        "format", "dc+sd-jwt",
                                        "meta", Map.of("vct_values", List.of("https://example.com/vct"))
                                ))
                        )
                ))
                .build();
        final SignedJWT signedJWT = new SignedJWT(header, claims);
        final JWK signingKey = KeyUtil.createJWKFromKeyPair(signingKeyPair);
        signedJWT.sign(new ECDSASigner(signingKey.toECKey()));
        return signedJWT.serialize();
    }

    private KeyPair generateEcKeyPair() {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (final NoSuchAlgorithmException | InvalidAlgorithmParameterException exception) {
            throw new IllegalStateException("Unable to generate an EC test key", exception);
        }
    }
}
