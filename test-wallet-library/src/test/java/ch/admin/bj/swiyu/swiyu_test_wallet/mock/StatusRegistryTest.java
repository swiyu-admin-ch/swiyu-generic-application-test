package ch.admin.bj.swiyu.swiyu_test_wallet.mock;

import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.registry.KeyUtil;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The Status Registry mock is the oracle for every status test, so its own behavior is checked here without MockServer:
 * which issuer signs a list, what it serves for a list nobody owns, and the {@code bits} and {@code lst} it serves.
 *
 * <p>Specification: Token Status List draft 20 §4.2 (`bits` is 1, 2, 4 or 8, `lst`) and §5.1 (Status List Token in JWT
 * format), Swiss VC profile (`typ` `statuslist+jwt`, `exp` and an absolute `kid`).
 */
class StatusRegistryTest {

    private RegisteredActors actors;
    private StatusRegistry registry;
    private IssuerConfig issuer;
    private IssuerConfig otherIssuer;

    @BeforeEach
    void setUp() {
        actors = new RegisteredActors();
        registry = new StatusRegistry(actors);
        issuer = newIssuer();
        otherIssuer = newIssuer();
        actors.addIssuer(issuer);
        actors.addIssuer(otherIssuer);
    }

    private static IssuerConfig newIssuer() {
        return IssuerConfig.createIssuerConfig(
                URI.create("https://mockserver:1080/api/v1/did/" + UUID.randomUUID()), false, null);
    }

    private static String id() {
        return UUID.randomUUID().toString();
    }

    private static boolean verifies(final String token, final IssuerConfig signer) throws Exception {
        return SignedJWT.parse(token).verify(
                new ECDSAVerifier(KeyUtil.createJWKFromKeyPair(signer.getKeyPair()).toECKey()));
    }

    /** What a Credential Issuer PUTs: a Status List Token with its own {@code bits} and {@code lst}. */
    private static String publishedToken(final IssuerConfig publisher, final int bits, final String lst) throws Exception {
        final SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("statuslist+jwt")).keyID("k").build(),
                new JWTClaimsSet.Builder().claim("status_list", Map.of("bits", bits, "lst", lst)).build());
        jwt.sign(ECCryptoSupport.createECDSASigner(publisher.getKeyPair().getPrivate()));
        return jwt.serialize();
    }

    @Test
    void statusListToken_whenNoIssuerOwnsTheList_thenIsEmptyInsteadOfAListSignedByAnotherIssuer() {
        assertThat(registry.statusListToken(id()))
                .isEmpty();
    }

    @Test
    void statusListToken_whenTheListWasCreatedForAnIssuersBusinessEntity_thenThatIssuerSignsIt() throws Exception {
        final String listId = id();

        registry.onStatusListCreated(issuer.getSwiyuPartnerId(), listId);

        final String token = registry.statusListToken(listId).orElseThrow();
        assertThat(verifies(token, issuer)).isTrue();
        assertThat(verifies(token, otherIssuer)).isFalse();
        final SignedJWT jwt = SignedJWT.parse(token);
        assertThat(jwt.getHeader().getType().getType())
                .isEqualTo("statuslist+jwt");
        assertThat(jwt.getHeader().getKeyID())
                .isEqualTo(issuer.getIssuerAssertKeyId());
        assertThat(jwt.getJWTClaimsSet().getIssuer())
                .isEqualTo(issuer.getIssuerDid());
        assertThat(jwt.getJWTClaimsSet().getExpirationTime().toInstant())
                .as("Swiss VC profile 5.1: exp is REQUIRED")
                .isAfter(Instant.now());
    }

    @Test
    void statusListToken_whenTheListWasCreatedForAnUnknownBusinessEntity_thenNobodyOwnsIt() {
        final String listId = id();

        registry.onStatusListCreated(UUID.randomUUID().toString(), listId);

        assertThat(registry.statusListToken(listId))
                .isEmpty();
    }

    @Test
    void statusListToken_whenTwoIssuersOwnOneListEach_thenEachListIsSignedByItsOwnIssuer() throws Exception {
        final String first = id();
        final String second = id();
        registry.onStatusListCreated(issuer.getSwiyuPartnerId(), first);
        registry.onStatusListCreated(otherIssuer.getSwiyuPartnerId(), second);

        assertThat(verifies(registry.statusListToken(first).orElseThrow(), issuer)).isTrue();
        assertThat(verifies(registry.statusListToken(second).orElseThrow(), otherIssuer)).isTrue();
    }

    @Test
    void statusListToken_whenTheOwnerIsSetExplicitly_thenItOverridesTheBusinessEntity() throws Exception {
        final String listId = id();
        registry.onStatusListCreated(issuer.getSwiyuPartnerId(), listId);

        registry.setCurrent(otherIssuer.getIssuerDid(), "https://mockserver:1080/api/v1/statuslist/" + listId + ".jwt");

        assertThat(verifies(registry.statusListToken(listId).orElseThrow(), otherIssuer)).isTrue();
    }

    @Test
    void statusListToken_whenTheIssuerPublishedAList_thenItsBitsAndLstAreServed() throws Exception {
        final String listId = id();
        registry.onStatusListCreated(issuer.getSwiyuPartnerId(), listId);

        registry.onStatusListPublished(listId, publishedToken(issuer, 4, "eNpjYAAAAAIAAQ"));

        final Map<String, Object> statusList = SignedJWT.parse(registry.statusListToken(listId).orElseThrow())
                .getJWTClaimsSet().getJSONObjectClaim("status_list");
        assertThat(statusList.get("bits"))
                .as("Token Status List §4.2: bits is a JSON integer, and it is the one the Credential Issuer chose")
                .isEqualTo(4L);
        assertThat(statusList.get("lst"))
                .isEqualTo("eNpjYAAAAAIAAQ");
    }

    @Test
    void statusListToken_whenNothingWasPublishedYet_thenServesAnEmptyTwoBitList() throws Exception {
        final String listId = id();
        registry.onStatusListCreated(issuer.getSwiyuPartnerId(), listId);

        final Map<String, Object> statusList = SignedJWT.parse(registry.statusListToken(listId).orElseThrow())
                .getJWTClaimsSet().getJSONObjectClaim("status_list");

        assertThat(statusList.get("bits")).isEqualTo(2L);
        assertThat((String) statusList.get("lst")).isNotBlank();
    }

    @Test
    void onStatusListPublished_whenTheBodyIsNotAStatusListToken_thenTheListIsKeptAsItWas() throws Exception {
        final String listId = id();
        registry.onStatusListCreated(issuer.getSwiyuPartnerId(), listId);
        registry.onStatusListPublished(listId, publishedToken(issuer, 8, "AAAA"));

        registry.onStatusListPublished(listId, "not a token");

        final Map<String, Object> statusList = SignedJWT.parse(registry.statusListToken(listId).orElseThrow())
                .getJWTClaimsSet().getJSONObjectClaim("status_list");
        assertThat(statusList.get("bits")).isEqualTo(8L);
    }

    @Test
    void statusListToken_whenTheSignatureFaultIsOn_thenTheTokenNoLongerVerifiesUntilTheFaultsAreReset() throws Exception {
        final String listId = id();
        registry.onStatusListCreated(issuer.getSwiyuPartnerId(), listId);

        registry.enableCorruptSignature();
        assertThat(registry.servesCorruptSignature()).isTrue();
        assertThat(verifies(registry.statusListToken(listId).orElseThrow(), issuer)).isFalse();

        registry.resetFaults();
        assertThat(registry.servesCorruptSignature()).isFalse();
        assertThat(verifies(registry.statusListToken(listId).orElseThrow(), issuer)).isTrue();
    }

    @Test
    void resetFaults_whenUpdatesWereFailing_thenTheyWorkAgain() {
        registry.enableUpdateError();
        assertThat(registry.updatesFail()).isTrue();

        registry.resetFaults();

        assertThat(registry.updatesFail()).isFalse();
    }
}
