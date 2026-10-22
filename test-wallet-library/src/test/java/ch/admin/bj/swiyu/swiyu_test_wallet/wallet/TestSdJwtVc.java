package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;

/**
 * An SD-JWT VC built straight from RFC 9901 and the Swiss VC profile, independently of the product and of
 * {@code swiyu-generic-java-lib}. It exists so wallet unit tests do not need a Credential Issuer.
 *
 * <p>Claims, as {@code ["name", "annual_salary", "address" {street_address, locality}, "nationalities" [CH, FR]]}:
 * every claim is selectively disclosable, the nested object uses a recursive Disclosure, and the array elements are
 * Disclosures of their own (RFC 9901 §4.2.2 and §4.2.4).
 */
// Credential fixture used by tests, not a JUnit test class.
@SuppressWarnings("PMD.TestClassWithoutTestCases")
final class TestSdJwtVc {

    static final String ISSUER_DID = "did:example:issuer";
    static final String ISSUER_KID = ISSUER_DID + "#assert-key-01";
    static final String VCT = "https://example.com/vct";

    private static final ObjectMapper JSON = JsonMapper.builder().build();

    private final ECKey issuerKey;
    private final String serializedIssuerJwt;
    private final String encodedNameDisclosure;
    private final String salaryDisclosure;
    private final String encodedStreetDisclosure;
    private final String encodedLocalityDisclosure;
    private final String encodedAddressDisclosure;
    private final String encodedChDisclosure;
    private final String encodedFrDisclosure;
    private final String encodedNationalitiesDisclosure;

    private TestSdJwtVc(final ECKey holderKey) {
        try {
            issuerKey = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).keyID(ISSUER_KID).generate();

            encodedNameDisclosure = disclosure("name", "John Doe");
            salaryDisclosure = disclosure("annual_salary", 120000);
            encodedStreetDisclosure = disclosure("street_address", "Main Street 1");
            encodedLocalityDisclosure = disclosure("locality", "Bern");
            encodedAddressDisclosure = disclosure("address", Map.of("_sd", List.of(digest(encodedStreetDisclosure), digest(encodedLocalityDisclosure))));
            encodedChDisclosure = arrayElementDisclosure("CH");
            encodedFrDisclosure = arrayElementDisclosure("FR");
            encodedNationalitiesDisclosure = disclosure("nationalities", List.of(
                    Map.of("...", digest(encodedChDisclosure)),
                    Map.of("...", digest(encodedFrDisclosure))));

            final Instant now = Instant.now();
            final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(ISSUER_DID)
                    .issueTime(Date.from(now))
                    .notBeforeTime(Date.from(now.minusSeconds(60)))
                    .expirationTime(Date.from(now.plusSeconds(3600)))
                    .claim("vct", VCT)
                    .claim("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()))
                    .claim("_sd_alg", "sha-256")
                    .claim("_sd", List.of(
                            digest(encodedNameDisclosure),
                            digest(salaryDisclosure),
                            digest(encodedAddressDisclosure),
                            digest(encodedNationalitiesDisclosure)))
                    .build();
            final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("dc+sd-jwt"))
                    .keyID(ISSUER_KID)
                    .customParam("profile_version", "swiss-profile-vc:1.0.0")
                    .build();
            final SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new ECDSASigner(issuerKey));
            serializedIssuerJwt = jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Issues the credential bound to {@code holderKey} through {@code cnf.jwk} (RFC 9901 §4.1.2). */
    static TestSdJwtVc issueFor(final ECKey holderKey) {
        return new TestSdJwtVc(holderKey);
    }

    ECKey issuerPublicKey() {
        return issuerKey.toPublicJWK();
    }

    /** {@code <Issuer-signed JWT>~<D1>~...~<DN>~}, every Disclosure, no Key Binding JWT. */
    String serialized() {
        return serializedIssuerJwt + "~" + String.join("~", allDisclosures()) + "~";
    }

    List<String> allDisclosures() {
        return List.of(encodedNameDisclosure, salaryDisclosure, encodedAddressDisclosure, encodedStreetDisclosure, encodedLocalityDisclosure,
                encodedNationalitiesDisclosure, encodedChDisclosure, encodedFrDisclosure);
    }

    String issuerSignedJwt() {
        return serializedIssuerJwt;
    }

    String nameDisclosure() {
        return encodedNameDisclosure;
    }

    String addressDisclosure() {
        return encodedAddressDisclosure;
    }

    String streetDisclosure() {
        return encodedStreetDisclosure;
    }

    String localityDisclosure() {
        return encodedLocalityDisclosure;
    }

    String nationalitiesDisclosure() {
        return encodedNationalitiesDisclosure;
    }

    String chDisclosure() {
        return encodedChDisclosure;
    }

    String frDisclosure() {
        return encodedFrDisclosure;
    }

    /** {@code [salt, claim name, claim value]}, base64url encoded (RFC 9901 §4.2.1). */
    private static String disclosure(final String name, final Object value) {
        return encode(JSON.writeValueAsString(List.of(UUID.randomUUID().toString(), name, value)));
    }

    /** {@code [salt, value]}, the Disclosure of an array element (RFC 9901 §4.2.2). */
    private static String arrayElementDisclosure(final Object value) {
        return encode(JSON.writeValueAsString(List.of(UUID.randomUUID().toString(), value)));
    }

    /** base64url of the SHA-256 hash of the ASCII bytes of the encoded Disclosure (RFC 9901 §4.2.3). */
    static String digest(final String encodedDisclosure) {
        return sha256Base64Url(encodedDisclosure);
    }

    static String sha256Base64Url(final String asciiText) {
        try {
            final byte[] hash = MessageDigest.getInstance("SHA-256").digest(asciiText.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String encode(final String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
