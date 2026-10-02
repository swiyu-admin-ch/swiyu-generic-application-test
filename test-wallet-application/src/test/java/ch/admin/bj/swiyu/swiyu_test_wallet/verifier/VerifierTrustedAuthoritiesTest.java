package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The Verifier tells the Wallet which issuers it accepts: the accepted issuer DIDs of the verification request become the
 * {@code trusted_authorities} of the credential query in the Request Object.
 *
 * <p>Specification: OID4VP 1.0 §6.1 and §6.1.1 ({@code trusted_authorities} is a non-empty array of objects with a {@code type}
 * and a non-empty array {@code values}), and Swiss verification profile §6.1.1 (the only type is {@code did}, its values are
 * the DIDs of the issuers the Verifier accepts). OID4VP §6.1 says a Wallet SHOULD only return credentials that match, and that
 * the Verifier must still verify the issuer on its own, which the Verifier does by filtering on the DID of the {@code kid}
 * (see {@code VerifierIssuerKeyResolutionTest}).
 */
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierTrustedAuthoritiesTest extends BaseTest {

    private static final String DID_AUTHORITY_TYPE = "did";

    @Test
    @XrayTest(
            key = "EIDOMNI-1177",
            summary = "Request Object carries the accepted issuer DIDs as did trusted authorities",
            description = """
                    Given a verification request with one accepted issuer DID.
                    When the Wallet fetches the Request Object.
                    Then its DCQL credential query contains one trusted authority of type did whose values are exactly the accepted issuer DID.
                    Spec: OID4VP 1.0 6.1.1, Swiss verification profile 6.1.1.
                    """)
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.HAPPY_PATH)
    void requestObject_whenOneIssuerIsAccepted_thenDcqlQueryHasADidTrustedAuthorityWithIt() throws ParseException {
        // Given
        final String acceptedIssuerDid = issuerConfig.getIssuerDid();
        final ManagementResponse verification = verifierManager.verificationRequest()
                .withDCQL()
                .acceptedIssuerDid(acceptedIssuerDid)
                .createManagementResponse();

        // When
        final Map<String, Object> credentialQuery = firstCredentialQuery(verification);

        // Then
        assertThat(trustedAuthorities(credentialQuery))
                .singleElement()
                .satisfies(authority -> {
                    assertThat(authority).containsEntry("type", DID_AUTHORITY_TYPE);
                    assertThat(values(authority)).containsExactly(acceptedIssuerDid);
                });
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1177",
            summary = "Request Object lists every accepted issuer DID in one did trusted authority",
            description = """
                    Given a verification request with two accepted issuer DIDs.
                    When the Wallet fetches the Request Object.
                    Then its DCQL credential query contains both DIDs as values of a trusted authority of type did.
                    Spec: OID4VP 1.0 6.1.1 (a value matches if it is one of the provided values), Swiss verification profile 6.1.1.
                    """)
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.HAPPY_PATH)
    void requestObject_whenSeveralIssuersAreAccepted_thenTheDidTrustedAuthorityListsAllOfThem() throws ParseException {
        // Given
        final String firstIssuerDid = issuerConfig.getIssuerDid();
        final String secondIssuerDid = "did:webvh:QmSecondAcceptedIssuer:mockserver%3A1080:api:v1:did:" + UUID.randomUUID();
        final ManagementResponse verification = verifierManager.verificationRequest()
                .withDCQL()
                .acceptedIssuerDids(List.of(firstIssuerDid, secondIssuerDid))
                .createManagementResponse();

        // When
        final Map<String, Object> credentialQuery = firstCredentialQuery(verification);

        // Then
        assertThat(trustedAuthorities(credentialQuery))
                .singleElement()
                .satisfies(authority -> {
                    assertThat(authority).containsEntry("type", DID_AUTHORITY_TYPE);
                    assertThat(values(authority)).containsExactlyInAnyOrder(firstIssuerDid, secondIssuerDid);
                });
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1177",
            summary = "Request Object has no trusted authorities when no issuer is listed",
            description = """
                    Given a verification request without accepted issuer DIDs.
                    When the Wallet fetches the Request Object.
                    Then its DCQL credential query has no trusted_authorities, because the array must be non-empty when present.
                    Spec: OID4VP 1.0 6.1 (trusted_authorities is a non-empty array), Swiss verification profile 6.1.1.
                    """)
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.EDGE_CASE)
    void requestObject_whenNoIssuerIsAccepted_thenDcqlQueryHasNoTrustedAuthorities() throws ParseException {
        // Given
        final ManagementResponse verification = verifierManager.verificationRequest()
                .withDCQL()
                .createManagementResponse();

        // When
        final Map<String, Object> credentialQuery = firstCredentialQuery(verification);

        // Then
        assertThat(credentialQuery)
                .as("trusted_authorities is OPTIONAL and, when present, a non-empty array (OID4VP 1.0 6.1)")
                .satisfiesAnyOf(
                        query -> assertThat(query).doesNotContainKey("trusted_authorities"),
                        query -> assertThat((List<?>) query.get("trusted_authorities")).isNotEmpty());
    }

    /** The first credential query of the DCQL query in the claims of the signed Request Object. */
    @SuppressWarnings("unchecked")
    private Map<String, Object> firstCredentialQuery(final ManagementResponse verification) throws ParseException {
        final String signedRequestObject = wallet.getVerificationDetailSigned(verification.getVerificationDeeplink());
        final Map<String, Object> dcqlQuery = SignedJWT.parse(signedRequestObject)
                .getJWTClaimsSet()
                .getJSONObjectClaim("dcql_query");
        assertThat(dcqlQuery).as("Request Object dcql_query").isNotNull();
        final List<Map<String, Object>> credentials = (List<Map<String, Object>>) dcqlQuery.get("credentials");
        assertThat(credentials).as("dcql_query.credentials").isNotEmpty();
        return credentials.getFirst();
    }

    @SuppressWarnings("unchecked")
    private static List<Object> values(final Map<String, Object> authority) {
        return (List<Object>) authority.get("values");
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> trustedAuthorities(final Map<String, Object> credentialQuery) {
        final Object authorities = credentialQuery.get("trusted_authorities");
        assertThat(authorities).as("trusted_authorities of the credential query").isInstanceOf(List.class);
        return (List<Map<String, Object>>) authorities;
    }
}
