package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.gen.verifier.model.DcqlClaimDto;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlCredentialDto;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlQueryDto;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.web.client.RestClient;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Characterizes which Disclosures the Wallet puts into a Presentation for a DCQL query
 * ({@link WalletBatchEntry#createSelectiveDisclosurePresentationForSdJwtIndex}).
 *
 * <p>Specification: OID4VP 1.0 §6.3 and §7 (Claims Query, Claims Path Pointer: a `null` path element selects every
 * array element, an integer selects one), §15.4.2 (only the strictly necessary claims), RFC 9901 §4.2 (Disclosures)
 * and §4.3.1 (the `sd_hash` covers the selected Disclosures). Every presentation is also run through the Verifier-side
 * validators of the library as a reference (see {@link SdJwtLibReference}).
 */
class SelectiveDisclosurePresentationTest {

    private static final String CLIENT_ID = "decentralized_identifier:did:tdw:example:verifier";
    private static final String NONCE = "n-0S6_WzA2Mj";

    private WalletBatchEntry entry;
    private TestSdJwtVc credential;

    @BeforeEach
    void setUp() {
        final Wallet wallet = new Wallet(RestClient.create(), null, null);
        entry = new WalletBatchEntry(wallet);
        entry.generateHolderKeys(1);
        credential = TestSdJwtVc.issueFor(entry.getHolderPublicKeys().getFirst());
        entry.addIssuedCredential(credential.serialized());
    }

    static Stream<Arguments> requestedClaimsAndExpectedDisclosures() {
        // The expected sets are written from the credential's structure, not taken from the wallet output.
        return Stream.of(
                Arguments.of("a top-level claim",
                        List.of(path("name")),
                        disclosures(c -> Set.of(c.nameDisclosure()))),
                Arguments.of("a claim inside a recursively disclosed object",
                        List.of(path("address", "locality")),
                        disclosures(c -> Set.of(c.addressDisclosure(), c.localityDisclosure()))),
                Arguments.of("every element of an array (null wildcard)",
                        List.of(path("nationalities", null)),
                        disclosures(c -> Set.of(c.nationalitiesDisclosure(), c.chDisclosure(), c.frDisclosure()))),
                Arguments.of("one array element by index",
                        List.of(path("nationalities", 1)),
                        disclosures(c -> Set.of(c.nationalitiesDisclosure(), c.frDisclosure()))),
                Arguments.of("several claims at once",
                        List.of(path("name"), path("address", "locality")),
                        disclosures(c -> Set.of(c.nameDisclosure(), c.addressDisclosure(), c.localityDisclosure())))
        );
    }

    /** Names the expected Disclosures before the credential (and its random salts) exists. */
    private static Function<TestSdJwtVc, Set<String>> disclosures(final Function<TestSdJwtVc, Set<String>> expected) {
        return expected;
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("requestedClaimsAndExpectedDisclosures")
    void presentation_whenClaimsRequested_thenDisclosesExactlyTheNecessaryDisclosures(
            final String description,
            final List<List<Object>> requestedPaths,
            final Function<TestSdJwtVc, Set<String>> expected
    ) throws Exception {
        final String presentation = entry.createSelectiveDisclosurePresentationForSdJwtIndex(0, request(requestedPaths));

        final List<String> parts = Arrays.asList(presentation.split("~", -1));
        assertThat(parts.getFirst())
                .as("the Issuer-signed JWT is presented unchanged")
                .isEqualTo(credential.issuerSignedJwt());
        assertThat(new LinkedHashSet<>(parts.subList(1, parts.size() - 1)))
                .as("the presented Disclosures: only what the query needs (OID4VP §15.4.2)")
                .isEqualTo(expected.apply(credential));

        final Map<String, Object> claims = SdJwtLibReference.verifyAndResolveClaims(
                presentation, credential.issuerPublicKey(), CLIENT_ID, NONCE);
        assertThat(claims)
                .as("the library's Verifier validators accept the presentation")
                .isNotEmpty();
    }

    @Test
    void presentation_whenAddressLocalityRequested_thenStreetStaysUndisclosed() throws Exception {
        final String presentation = entry.createSelectiveDisclosurePresentationForSdJwtIndex(
                0, request(List.of(path("address", "locality"))));

        final Map<String, Object> claims = SdJwtLibReference.verifyAndResolveClaims(
                presentation, credential.issuerPublicKey(), CLIENT_ID, NONCE);

        assertThat(claims)
                .containsKey("address")
                .doesNotContainKeys("name", "annual_salary", "nationalities");
        assertThat(addressOf(claims))
                .containsEntry("locality", "Bern")
                .doesNotContainKey("street_address");
    }

    @Test
    void presentation_whenNoClaimIsRequested_thenSeparatesTheIssuerJwtAndTheKeyBindingJwtWithATilde() throws Exception {
        final String presentation = entry.createSelectiveDisclosurePresentationForSdJwtIndex(0, request(List.of()));

        assertThat(presentation)
                .as("RFC 9901 §4.3: <Issuer-signed JWT>~<KB-JWT> when no Disclosure is selected")
                .startsWith(credential.issuerSignedJwt() + "~");
        final String keyBindingJwt = presentation.substring((credential.issuerSignedJwt() + "~").length());
        assertThat(keyBindingJwt)
                .doesNotContain("~");
        assertThat(SdJwtLibReference.verifyAndResolveClaims(
                presentation, credential.issuerPublicKey(), CLIENT_ID, NONCE))
                .doesNotContainKeys("name", "annual_salary", "address", "nationalities");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> addressOf(final Map<String, Object> claims) {
        return (Map<String, Object>) claims.get("address");
    }

    private static List<Object> path(final Object... elements) {
        return new ArrayList<>(Arrays.asList(elements));
    }

    private static RequestObject request(final List<List<Object>> paths) {
        final DcqlCredentialDto credentialQuery = new DcqlCredentialDto()
                .id("credential_query")
                .format("dc+sd-jwt")
                .claims(paths.stream().map(p -> new DcqlClaimDto().path(p)).toList());
        return new RequestObject()
                .clientId(CLIENT_ID)
                .nonce(NONCE)
                .dcqlQuery(new DcqlQueryDto().addCredentialsItem(credentialQuery));
    }
}
