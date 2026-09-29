package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialClaimsConstants;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialClaimsFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.VerificationClaimsBuilder;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierDcqlMissingDisclosureE2ETest extends BaseTest {

    private static final int REQUESTED_DEGREE_INDEX = 0;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    @XrayTest(
            key = "EIDOMNI-1258",
            summary = "Verifier rejects an undisclosed object requested by a DCQL array index",
            description = """
                    Given a bound SD-JWT credential containing an array of degree objects.
                    And a DCQL query requests the first degree object by its array index.
                    When a malicious wallet omits that object's disclosure and submits a freshly bound presentation.
                    Then the verifier rejects the presentation instead of treating the undisclosed object as present.
                    """
    )
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC, ImageTags.STAGING},
            reason = "The missing array-element disclosure fix is not available on these verifier images"
    )
    void dcqlPresentation_whenRequestedObjectDisclosureIsOmitted_thenVerifierRejects() throws JacksonException {
        // Given: Business Issuer creates a credential containing selectively disclosable degree objects.
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_IDENTITY_PROFILE_SD_JWT,
                CredentialClaimsFixtures.createBaseProfile()
        );
        final WalletBatchEntry batchEntry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withDCQL(VerificationClaimsBuilder.claims()
                        .arrayIndex(CredentialClaimsConstants.KEY_DEGREES, REQUESTED_DEGREE_INDEX)
                        .build())
                .createManagementResponse();
        final RequestObject requestObject = wallet.getVerificationRequestObject(
                verification.getVerificationDeeplink()
        );

        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

        // Given: a malicious wallet omits the disclosure subtree for degrees[0].
        final String issuedSdJwt = batchEntry.getIssuedCredentials().getFirst();
        final String[] sdJwtParts = issuedSdJwt.split("~", -1);
        final List<String> disclosures = Arrays.stream(sdJwtParts)
                .skip(1)
                .filter(part -> !part.isBlank())
                .toList();
        final List<List<Object>> degreesClaimDisclosures = new ArrayList<>();

        for (final String disclosure : disclosures) {
            final List<Object> disclosureParts = decodeDisclosure(disclosure);
            if (disclosureParts.size() == 3
                    && CredentialClaimsConstants.KEY_DEGREES.equals(disclosureParts.get(1))) {
                degreesClaimDisclosures.add(disclosureParts);
            }
        }

        assertThat(degreesClaimDisclosures)
                .as("The issued credential must contain exactly one disclosure for the degrees claim")
                .singleElement();

        final Object disclosedDegreesValue = degreesClaimDisclosures.getFirst().get(2);
        assertThat(disclosedDegreesValue)
                .as("The degrees disclosure must contain an array")
                .isInstanceOf(List.class);

        final List<?> disclosedDegrees = (List<?>) disclosedDegreesValue;
        assertThat(disclosedDegrees)
                .as("The requested degree index must exist in the issued credential")
                .hasSizeGreaterThan(REQUESTED_DEGREE_INDEX);
        assertThat(disclosedDegrees.get(REQUESTED_DEGREE_INDEX))
                .as("The requested degree must be selectively disclosable")
                .isInstanceOf(Map.class);

        final Map<?, ?> requestedDegreeWrapper = (Map<?, ?>) disclosedDegrees.get(REQUESTED_DEGREE_INDEX);
        final Object requestedDegreeDigestValue = requestedDegreeWrapper.get("...");
        assertThat(requestedDegreeDigestValue)
                .as("The requested degree wrapper must reference its disclosure digest")
                .isInstanceOf(String.class);

        final String requestedDegreeDigest = (String) requestedDegreeDigestValue;
        final Map<String, String> disclosuresByDigest = new LinkedHashMap<>();
        disclosures.forEach(disclosure -> disclosuresByDigest.put(disclosureDigest(disclosure), disclosure));
        final String requestedObjectDisclosure = disclosuresByDigest.get(requestedDegreeDigest);

        assertThat(requestedObjectDisclosure)
                .as("The issued credential must contain the disclosure referenced by degrees[0]")
                .isNotNull();

        final Set<String> omittedDisclosures = disclosureSubtree(
                requestedDegreeDigest,
                disclosuresByDigest
        );
        final List<String> presentedDisclosures = disclosures.stream()
                .filter(disclosure -> !omittedDisclosures.contains(disclosure))
                .toList();

        assertThat(omittedDisclosures)
                .as("The malicious presentation must omit the requested degree object and its nested disclosures")
                .contains(requestedObjectDisclosure)
                .hasSizeGreaterThan(1);
        assertThat(presentedDisclosures)
                .as("No disclosure from the omitted degree subtree may remain in the presentation")
                .doesNotContainAnyElementsOf(omittedDisclosures);

        final String sdJwtWithoutRequestedObject = sdJwtParts[0]
                + "~"
                + String.join("~", presentedDisclosures)
                + "~";
        batchEntry.clearIssuedCredentials();
        batchEntry.addIssuedCredential(sdJwtWithoutRequestedObject);

        assertThat(batchEntry.getIssuedCredentials())
                .as("The wallet must bind the presentation to the incomplete SD-JWT")
                .containsExactly(sdJwtWithoutRequestedObject);

        final String presentation = batchEntry.createPresentationForSdJwtIndex(0, requestObject);

        // When: Wallet OID4VP submits the validly bound but incomplete presentation.
        final HttpClientErrorException error = assertThrows(
                HttpClientErrorException.class,
                () -> wallet.respondToVerification(requestObject, presentation)
        );

        // Then: Verifier rejects the missing object and persists the failed terminal state.
        ApiErrorAssert.assertThat(error)
                .hasStatus(400)
                .hasErrorDescription("Requested DCQL path could not be found - Missing claim at index 0");
        verifierManager.verifyState(verification.getId(), VerificationStatus.FAILED);
    }

    private List<Object> decodeDisclosure(final String disclosure) throws JacksonException {
        final byte[] decoded = Base64.getUrlDecoder().decode(disclosure);
        return OBJECT_MAPPER.readValue(
                decoded,
                new TypeReference<List<Object>>() {
                }
        );
    }

    private String disclosureDigest(final String disclosure) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] hash = digest.digest(disclosure.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(hash);
        } catch (final NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 must be available", exception);
        }
    }

    private Set<String> disclosureSubtree(
            final String rootDigest,
            final Map<String, String> disclosuresByDigest
    ) throws JacksonException {
        final Set<String> subtree = new LinkedHashSet<>();
        final Deque<String> pendingDigests = new ArrayDeque<>();
        pendingDigests.add(rootDigest);

        while (!pendingDigests.isEmpty()) {
            final String disclosure = disclosuresByDigest.get(pendingDigests.removeFirst());
            if (disclosure == null || !subtree.add(disclosure)) {
                continue;
            }
            final List<Object> disclosureParts = decodeDisclosure(disclosure);
            collectReferencedDigests(disclosureParts.getLast(), pendingDigests);
        }
        return subtree;
    }

    private void collectReferencedDigests(final Object value, final Deque<String> digests) {
        if (value instanceof Map<?, ?> objectValue) {
            final Object arrayElementDigest = objectValue.get("...");
            if (arrayElementDigest instanceof String digest) {
                digests.add(digest);
            }

            final Object objectPropertyDigests = objectValue.get("_sd");
            if (objectPropertyDigests instanceof List<?> digestList) {
                digestList.stream()
                        .filter(String.class::isInstance)
                        .map(String.class::cast)
                        .forEach(digests::add);
            }

            objectValue.entrySet().stream()
                    .filter(entry -> !"...".equals(entry.getKey()) && !"_sd".equals(entry.getKey()))
                    .map(Map.Entry::getValue)
                    .forEach(nestedValue -> collectReferencedDigests(nestedValue, digests));
        } else if (value instanceof List<?> arrayValue) {
            arrayValue.forEach(nestedValue -> collectReferencedDigests(nestedValue, digests));
        }
    }
}
