package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialClaimsFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtParser;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JsonConverter;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto.Sha256Base64Url;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import tools.jackson.databind.JsonNode;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class IssuerNullClaimsTest extends BaseTest {

    @ParameterizedTest(name = "Null claim: {0}")
    @ValueSource(strings = {"job_title", "years_of_experience", "profile_picture"})
    @XrayTest(
            key = "EIDOMNI-1444",
            summary = "Credential Issuer preserves explicit null claims in every issued SD-JWT VC",
            description = """
                    Given a Credential Offer with an explicit null claim and other populated claims.
                    When the Wallet collects the Credentials through OID4VCI.
                    Then every Credential contains the null value in a three-element Disclosure,
                    preserves the other values, omits absent claims, and binds each Disclosure to the signed payload.
                    Spec: RFC 9901 §4.2.1, §4.2.3, §4.2.4.1; OID4VCI 1.0 §8.3.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCI_I1_ISSUING_VERIFIABLE_CREDENTIALS)
    @Tag(ReportingTags.UCI_I1A_CREATE_VERIFIABLE_CREDENTIALS)
    void credentialIssuance_whenSubjectClaimIsNull_thenPreservesNullInEveryCredential(final String nullClaim) throws Exception {
        // Given
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.mandatoryClaimsEmployeeProfile();
        subjectClaims.put(nullClaim, null);
        final List<String> optionalClaims = List.of("job_title", "years_of_experience", "profile_picture");

        // When
        final var offer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT, subjectClaims);
        final var entry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        // Then
        SdJwtBatchAssert.assertThat(entry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique();
        final ECDSAVerifier issuerVerifier = new ECDSAVerifier((ECPublicKey) issuerConfig.getKeyPair().getPublic());
        final Map<String, Object> actualClaims = new HashMap<>();
        for (final String sdJwt : entry.getIssuedCredentials()) {
            actualClaims.clear();
            final SignedJWT issuerJwt = SignedJWT.parse(sdJwt.split("~")[0]);
            assertThat(issuerJwt.verify(issuerVerifier))
                    .as("Credential Issuer signature")
                    .isTrue();
            final JsonNode payload = JsonConverter.toJsonNode(SdJwtParser.payload(sdJwt));
            final Map<String, JsonNode> disclosures = decodeDisclosures(sdJwt);
            for (final var disclosure : disclosures.entrySet()) {
                final JsonNode parts = disclosure.getValue();
                assertThat(parts.size())
                        .as("Object-property Disclosure contains salt, claim name, and value")
                        .isEqualTo(3);
                final String claimName = parts.get(1).asText();
                assertThat(actualClaims)
                        .as("Each claim has exactly one Disclosure")
                        .doesNotContainKey(claimName);
                actualClaims.put(claimName, JsonConverter.objectMapper().convertValue(parts.get(2), Object.class));
                assertThat(JsonConverter.toStringList(payload.get("_sd")))
                        .as("Disclosure for %s is bound to the signed payload", claimName)
                        .contains(disclosure.getKey());
                assertThat(payload.has(claimName))
                        .as("Subject claim %s remains selectively disclosable", claimName)
                        .isFalse();
            }
            assertThat(actualClaims)
                    .containsExactlyInAnyOrderEntriesOf(subjectClaims)
                    .containsKey(nullClaim);
            assertThat(actualClaims.get(nullClaim))
                    .as("Explicit null is preserved")
                    .isNull();
            assertThat(actualClaims.keySet())
                    .doesNotContainAnyElementsOf(optionalClaims.stream().filter(claim -> !claim.equals(nullClaim)).toList());
        }
        assertThat(issuerManager.getStatusById(offer.getManagementId()).getStatus())
                .isEqualTo(CredentialStatusType.ISSUED);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1445",
            summary = "Credential Issuer preserves null properties in nested subject objects",
            description = """
                    Given a Credential Offer whose address contains a null street address, a populated locality, and no postal code.
                    When the Wallet collects the Credentials through OID4VCI.
                    Then every Credential retains the null property in a recursive Disclosure,
                    retains the locality, omits the postal code, and binds both child Disclosures to the address.
                    Spec: RFC 9901 §4.2.1, §4.2.3, §4.2.6; Swiss VC profile 1.0 §4.2.6.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCI_I1_ISSUING_VERIFIABLE_CREDENTIALS)
    @Tag(ReportingTags.UCI_I1A_CREATE_VERIFIABLE_CREDENTIALS)
    void credentialIssuance_whenNestedSubjectPropertyIsNull_thenPreservesNullAndSibling() throws Exception {
        // Given
        final Map<String, Object> subjectClaims = CredentialClaimsFixtures.createBaseProfile();
        final Map<String, Object> address = new HashMap<>();
        address.put("street_address", null);
        address.put("locality", "Bern");
        subjectClaims.put("address", address);

        // When
        final var offer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_IDENTITY_PROFILE_SD_JWT, subjectClaims);
        final var entry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        // Then
        SdJwtBatchAssert.assertThat(entry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique();
        final ECDSAVerifier issuerVerifier = new ECDSAVerifier((ECPublicKey) issuerConfig.getKeyPair().getPublic());
        final Map<String, Object> actualAddress = new HashMap<>();
        for (final String sdJwt : entry.getIssuedCredentials()) {
            actualAddress.clear();
            final SignedJWT issuerJwt = SignedJWT.parse(sdJwt.split("~")[0]);
            assertThat(issuerJwt.verify(issuerVerifier))
                    .as("Credential Issuer signature")
                    .isTrue();
            final JsonNode payload = JsonConverter.toJsonNode(SdJwtParser.payload(sdJwt));
            final Map<String, JsonNode> disclosures = decodeDisclosures(sdJwt);
            final var addressDisclosures = disclosures.entrySet().stream()
                    .filter(disclosure -> disclosure.getValue().size() == 3 && "address".equals(disclosure.getValue().get(1).asText()))
                    .toList();
            assertThat(addressDisclosures)
                    .as("Address Disclosure")
                    .hasSize(1);
            final var addressDisclosure = addressDisclosures.getFirst();
            assertThat(JsonConverter.toStringList(payload.get("_sd")))
                    .contains(addressDisclosure.getKey());
            final List<String> childDigests = JsonConverter.toStringList(addressDisclosure.getValue().get(2).get("_sd"));
            assertThat(childDigests)
                    .as("Only the two supplied address properties are disclosed")
                    .hasSize(2);
            for (final String digest : childDigests) {
                assertThat(disclosures)
                        .containsKey(digest);
                final JsonNode parts = disclosures.get(digest);
                assertThat(parts.size())
                        .isEqualTo(3);
                final String claimName = parts.get(1).asText();
                assertThat(actualAddress)
                        .doesNotContainKey(claimName);
                actualAddress.put(claimName, JsonConverter.objectMapper().convertValue(parts.get(2), Object.class));
            }
            assertThat(actualAddress)
                    .containsExactlyInAnyOrderEntriesOf(address)
                    .containsKey("street_address")
                    .doesNotContainKey("postal_code");
            assertThat(actualAddress.get("street_address"))
                    .isNull();
        }
        assertThat(issuerManager.getStatusById(offer.getManagementId()).getStatus())
                .isEqualTo(CredentialStatusType.ISSUED);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1446",
            summary = "Credential Issuer preserves null array elements and their positions",
            description = """
                    Given a Credential Offer whose nationalities array contains CH, null, and FR in that order.
                    When the Wallet collects the Credentials through OID4VCI.
                    Then every Credential contains all three elements in order, including a two-element Disclosure for null,
                    with Disclosure digests bound to the array and the signed payload.
                    Spec: RFC 9901 §4.2.2, §4.2.3, §4.2.4.2; Swiss VC profile 1.0 §4.2.2.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCI_I1_ISSUING_VERIFIABLE_CREDENTIALS)
    @Tag(ReportingTags.UCI_I1A_CREATE_VERIFIABLE_CREDENTIALS)
    void credentialIssuance_whenSubjectArrayContainsNull_thenPreservesNullPosition() throws Exception {
        // Given
        final Map<String, Object> subjectClaims = CredentialClaimsFixtures.createBaseProfile();
        final List<String> nationalities = Arrays.asList("CH", null, "FR");
        subjectClaims.put("nationalities", nationalities);

        // When
        final var offer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_IDENTITY_PROFILE_SD_JWT, subjectClaims);
        final var entry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        // Then
        SdJwtBatchAssert.assertThat(entry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique();
        final ECDSAVerifier issuerVerifier = new ECDSAVerifier((ECPublicKey) issuerConfig.getKeyPair().getPublic());
        for (final String sdJwt : entry.getIssuedCredentials()) {
            final SignedJWT issuerJwt = SignedJWT.parse(sdJwt.split("~")[0]);
            assertThat(issuerJwt.verify(issuerVerifier))
                    .as("Credential Issuer signature")
                    .isTrue();
            final JsonNode payload = JsonConverter.toJsonNode(SdJwtParser.payload(sdJwt));
            final Map<String, JsonNode> disclosures = decodeDisclosures(sdJwt);
            final var arrayDisclosures = disclosures.entrySet().stream()
                    .filter(disclosure -> disclosure.getValue().size() == 3 && "nationalities".equals(disclosure.getValue().get(1).asText()))
                    .toList();
            assertThat(arrayDisclosures)
                    .as("Nationalities Disclosure")
                    .hasSize(1);
            final var arrayDisclosure = arrayDisclosures.getFirst();
            assertThat(JsonConverter.toStringList(payload.get("_sd")))
                    .contains(arrayDisclosure.getKey());
            final JsonNode array = arrayDisclosure.getValue().get(2);
            assertThat(array.isArray())
                    .isTrue();
            assertThat(array.size())
                    .isEqualTo(nationalities.size());
            for (int index = 0; index < nationalities.size(); index++) {
                final JsonNode reference = array.get(index);
                assertThat(reference.size())
                        .as("Array element %s contains only its Disclosure digest", index)
                        .isEqualTo(1);
                final String digest = reference.get("...").asText();
                assertThat(disclosures)
                        .containsKey(digest);
                final JsonNode parts = disclosures.get(digest);
                assertThat(parts.size())
                        .as("Array-element Disclosure contains salt and value")
                        .isEqualTo(2);
                assertThat(JsonConverter.objectMapper().convertValue(parts.get(1), Object.class))
                        .as("Nationalities element at index %s", index)
                        .isEqualTo(nationalities.get(index));
            }
        }
        assertThat(issuerManager.getStatusById(offer.getManagementId()).getStatus())
                .isEqualTo(CredentialStatusType.ISSUED);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1447",
            summary = "Credential Issuer preserves null claims supplied by a deferred subject update",
            description = """
                    Given a deferred Credential Offer with a populated job title and no issued Credentials.
                    When the Issuer Business System replaces the job title with null and the Wallet collects the deferred Credentials.
                    Then every Credential contains the explicit null, preserves the other claims, and the issuance becomes ISSUED.
                    Spec: RFC 9901 §4.2.1, §4.2.3; OID4VCI 1.0 §9.2.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCI_I1_ISSUING_VERIFIABLE_CREDENTIALS)
    @Tag(ReportingTags.UCI_I1B_CREATE_DEFERRED_VERIFIABLE_CREDENTIALS)
    void deferredCredentialIssuance_whenSubjectUpdateReplacesValueWithNull_thenPreservesNull() throws Exception {
        // Given
        final Map<String, Object> initialClaims = CredentialSubjectFixtures.mandatoryClaimsEmployeeProfile();
        initialClaims.put("job_title", "Engineer");
        final var offer = issuerManager.createDeferredCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT, initialClaims);
        final var entry = wallet.collectTransactionIdFromDeferredOffer(toUri(offer.getOfferDeeplink()));
        assertThat(issuerManager.getStatusById(offer.getManagementId()).getStatus())
                .isEqualTo(CredentialStatusType.DEFERRED);
        assertThat(entry.getTransactionId())
                .isNotNull();
        assertThat(entry.getIssuedCredentials())
                .isNullOrEmpty();

        // When
        final Map<String, Object> updatedClaims = new HashMap<>(initialClaims);
        updatedClaims.put("job_title", null);
        issuerManager.updateCredentialForDeferredFlowRequestCreation(offer.getManagementId(), updatedClaims);
        assertThat(issuerManager.getStatusById(offer.getManagementId()).getStatus())
                .isEqualTo(CredentialStatusType.READY);
        wallet.getCredentialFromTransactionId(entry);

        // Then
        SdJwtBatchAssert.assertThat(entry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique();
        final ECDSAVerifier issuerVerifier = new ECDSAVerifier((ECPublicKey) issuerConfig.getKeyPair().getPublic());
        final Map<String, Object> actualClaims = new HashMap<>();
        for (final String sdJwt : entry.getIssuedCredentials()) {
            actualClaims.clear();
            final SignedJWT issuerJwt = SignedJWT.parse(sdJwt.split("~")[0]);
            assertThat(issuerJwt.verify(issuerVerifier))
                    .as("Credential Issuer signature")
                    .isTrue();
            final JsonNode payload = JsonConverter.toJsonNode(SdJwtParser.payload(sdJwt));
            for (final var disclosure : decodeDisclosures(sdJwt).entrySet()) {
                final JsonNode parts = disclosure.getValue();
                assertThat(parts.size())
                        .isEqualTo(3);
                final String claimName = parts.get(1).asText();
                assertThat(actualClaims)
                        .doesNotContainKey(claimName);
                actualClaims.put(claimName, JsonConverter.objectMapper().convertValue(parts.get(2), Object.class));
                assertThat(JsonConverter.toStringList(payload.get("_sd")))
                        .contains(disclosure.getKey());
                assertThat(payload.has(claimName))
                        .isFalse();
            }
            assertThat(actualClaims)
                    .containsExactlyInAnyOrderEntriesOf(updatedClaims)
                    .containsKey("job_title");
            assertThat(actualClaims.get("job_title"))
                    .as("The deferred update replaces the previous value with explicit null")
                    .isNull();
        }
        assertThat(issuerManager.getStatusById(offer.getManagementId()).getStatus())
                .isEqualTo(CredentialStatusType.ISSUED);
    }

    // Each Disclosure contains different UTF-8 bytes and therefore needs its own decoded String.
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    private static Map<String, JsonNode> decodeDisclosures(final String sdJwt) {
        final Map<String, JsonNode> disclosures = new HashMap<>();
        for (final String raw : SdJwtParser.rawDisclosures(sdJwt)) {
            final String json = new String(Base64.getUrlDecoder().decode(raw), StandardCharsets.UTF_8);
            disclosures.put(Sha256Base64Url.ofUsAscii(raw), JsonConverter.toJsonNode(json));
        }
        return disclosures;
    }
}
