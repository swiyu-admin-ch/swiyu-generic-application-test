package ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.TrustConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockserver.model.HttpRequest;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class Tp2TrustRegistryMockSupportTest {

    private Tp2TrustRegistryStatementFactory statementFactory;
    private Tp2MockServerResponseFactory responseFactory;
    private IssuerConfig issuerConfig;
    private TrustConfig trustConfig;

    @BeforeEach
    void setUp() {
        trustConfig = buildTrustConfig();
        issuerConfig = buildIssuerConfig();
        statementFactory = new Tp2TrustRegistryStatementFactory(issuerConfig, trustConfig);
        responseFactory = new Tp2MockServerResponseFactory(new ObjectMapper().findAndRegisterModules());
    }

    @Test
    void identityTrustStatement_whenBuilt_thenContainsExpectedTp2Metadata() throws ParseException {
        SignedJWT statement = SignedJWT.parse(statementFactory.buildIdentityTrustStatement(issuerConfig.getIssuerDid()));

        assertThat(statement.getHeader().getType().toString()).isEqualTo("swiyu-identity-trust-statement+jwt");
        assertThat(statement.getHeader().getCustomParam("profile_version"))
                .isEqualTo(Tp2TrustRegistryStatementFactory.TP2_PROFILE_VERSION);
        assertThat(statement.getJWTClaimsSet().getIssuer()).isEqualTo(trustConfig.getTrustDid());
        assertThat(statement.getJWTClaimsSet().getSubject()).isEqualTo(issuerConfig.getIssuerDid());
        assertThat(statement.getJWTClaimsSet().getStringClaim("entity_name")).isEqualTo("Mock TP2 Issuer");
    }

    @Test
    void protectedIssuanceAuthorization_whenBuilt_thenContainsAuthorizedVctValues() throws ParseException {
        SignedJWT statement = SignedJWT.parse(
                statementFactory.buildProtectedIssuanceAuthorizationStatement(
                        issuerConfig.getIssuerDid(),
                        statementFactory.protectedIssuanceAuthorizationJti()
                )
        );

        assertThat(statement.getJWTClaimsSet().getBooleanClaim("authorized")).isTrue();
        assertThat(statement.getJWTClaimsSet().getStringListClaim("vct_values"))
                .containsExactly(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
    }

    @Test
    void identityTrustStatements_whenNoSubjectRequested_thenReturnIssuerAndVerifierStatements() {
        List<String> statements = statementFactory.buildIdentityTrustStatements(null);

        assertThat(statements).hasSize(2);
    }

    @Test
    void pagedContent_whenPageAndSizeRequested_thenEchoesPagingShape() {
        HttpRequest request = HttpRequest.request()
                .withQueryStringParameter("page", "2")
                .withQueryStringParameter("size", "5");

        Map<String, Object> response = responseFactory.pagedContent(List.of("a", "b"), request);
        @SuppressWarnings("unchecked")
        List<String> content = (List<String>) response.get("content");
        @SuppressWarnings("unchecked")
        Map<String, Object> page = (Map<String, Object>) response.get("page");

        assertThat(response).containsKeys("content", "page");
        assertThat(content).containsExactly("a", "b");
        assertThat(page).containsEntry("number", 2)
                .containsEntry("size", 5)
                .containsEntry("totalElements", 2);
    }

    private static TrustConfig buildTrustConfig() {
        KeyPair trustKeyPair = generateEcKeyPair();
        return TrustConfig.builder()
                .trustDid("did:tdw:mock-trust-registry")
                .trustDidLog("mock-trust-did-log")
                .trustAssertKeyId("did:tdw:mock-trust-registry#assert-key-01")
                .trustAuthKeyId("did:tdw:mock-trust-registry#auth-key-01")
                .trustAssertKeyPemString(toPem(trustKeyPair))
                .trustAuthKeyPemString(toPem(trustKeyPair))
                .build();
    }

    private static IssuerConfig buildIssuerConfig() {
        KeyPair issuerKeyPair = generateEcKeyPair();
        return IssuerConfig.builder()
                .issuerDid("did:tdw:mock-issuer")
                .issuerDidLog("mock-issuer-did-log")
                .issuerAssertKeyId("did:tdw:mock-issuer#assert-key-01")
                .issuerAuthKeyId("did:tdw:mock-issuer#auth-key-01")
                .issuerAssertKeyPemString(toPem(issuerKeyPair))
                .issuerAuthKeyPemString(toPem(issuerKeyPair))
                .keyPair(issuerKeyPair)
                .build();
    }

    private static KeyPair generateEcKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Cannot generate EC test key pair", e);
        }
    }

    private static String toPem(KeyPair keyPair) {
        String privateKeyBase64 = Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(keyPair.getPrivate().getEncoded());
        String publicKeyBase64 = Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(keyPair.getPublic().getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + privateKeyBase64 + "\n-----END PRIVATE KEY-----\n"
                + "-----BEGIN PUBLIC KEY-----\n" + publicKeyBase64 + "\n-----END PUBLIC KEY-----\n";
    }
}
