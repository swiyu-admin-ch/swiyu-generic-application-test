package ch.admin.bj.swiyu.swiyu_test_wallet.flows;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlClaimDto;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpClientErrorException;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@Slf4j
public class SubjectClaimsTest extends BaseTest {

    static Stream<Arguments> sdJwtSelectiveDisclosureScenariosSuccessful() {
        return Stream.of(

                // Scalar: string --

                Arguments.of(
                        "String scalar: disclose 'name' without value constraint",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("name")
                                .build()
                ),

                Arguments.of(
                        "String scalar: disclose 'name' with exact matching value",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("name", List.of(CredentialClaimsConstants.DEFAULT_NAME))
                                .build()
                ),

                Arguments.of(
                        "String scalar: disclose 'additional_info' without value constraint",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("additional_info")
                                .build()
                ),

                // Scalar: number --

                Arguments.of(
                        "Number scalar: disclose 'birth_year' without value constraint",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("birth_year")
                                .build()
                ),

                Arguments.of(
                        "Number scalar: disclose 'birth_year' with exact matching value",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("birth_year", List.of(CredentialClaimsConstants.DEFAULT_BIRTH_YEAR))
                                .build()
                ),

                // Scalar: image (base64/URL string stored as string) --

                Arguments.of(
                        "Image scalar: disclose 'portrait' without value constraint",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("portrait")
                                .build()
                ),

                Arguments.of(
                        "Image scalar: disclose 'portrait' with exact matching value",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("portrait", List.of(CredentialClaimsConstants.DEFAULT_PORTRAIT))
                                .build()
                ),

                // Object (nested) --

                Arguments.of(
                        "Object: disclose top-level 'address' without value constraint",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("address")
                                .build()
                ),

                Arguments.of(
                        "Object: disclose nested field 'address.locality' without value constraint",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .nested("address", "locality")
                                .build()
                ),

                Arguments.of(
                        "Object: disclose nested field 'address.postal_code' with exact matching value",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .nested("address", "postal_code")
                                .build()
                ),

                // Array of strings --

                Arguments.of(
                        "String array: disclose all elements of 'nationalities'",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayAll("nationalities")
                                .build()
                ),

                Arguments.of(
                        "String array: disclose first element of 'nationalities' by index",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayIndex("nationalities", 0)
                                .build()
                ),

                Arguments.of(
                        "String array: disclose last element of 'nationalities' by index and value match",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayIndex("nationalities", 1, List.of("Betelgeusian"))
                                .build()
                ),

                // Array of numbers --

                Arguments.of(
                        "Number array: disclose all elements of 'favorite_numbers'",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayAll("favorite_numbers")
                                .build()
                ),

                Arguments.of(
                        "Number array: disclose first element of 'favorite_numbers' by index",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayIndex("favorite_numbers", 0)
                                .build()
                ),

                // Array of objects --

                Arguments.of(
                        "Object array: disclose all elements of 'degrees'",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayAll("degrees")
                                .build()
                ),

                Arguments.of(
                        "Object array: disclose first element of 'degrees' by index",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayIndex("degrees", 0)
                                .build()
                ),

                Arguments.of(
                        "Object array: disclose second element of 'degrees' by index",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayIndex("degrees", 1)
                                .build()
                ),

                Arguments.of(
                        "Object array: disclose nested field 'degrees[*].type' without value constraint",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayField("degrees", "type")
                                .build()
                ),

                Arguments.of(
                        "Object array: disclose nested field 'degrees[*].university' without value constraint",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayField("degrees", "university")
                                .build()
                ),

                Arguments.of(
                        "Object array: disclose 'degrees[*].type' with matching value 'Bachelor of Science'",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayField("degrees", "type", List.of(CredentialClaimsConstants.DEGREE_TYPE_BACHELOR))
                                .build()
                ),

                Arguments.of(
                        "Object array: disclose 'degrees[*].type' with matching value 'Master of Science'",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayField("degrees", "type", List.of(CredentialClaimsConstants.DEGREE_TYPE_MASTER))
                                .build()
                ),

                // Mixed-type array --

                Arguments.of(
                        "Mixed-type array: disclose all elements of 'additional_info_list'",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayAll("additional_info_list")
                                .build()
                ),

                Arguments.of(
                        "Mixed-type array: 'additional_info_list' has 3 strings + 2 numbers, verifier expects number 42 to be present — success",
                        CredentialClaimsBuilder.base()
                                .withArray("additional_info_list", List.of("alpha", "beta", "gamma", 7, "42"))
                                .build(),
                        VerificationClaimsBuilder.claims()
                                .arrayAllWithValues("additional_info_list", List.of("42"))
                                .build()
                ),

                // Combinations --

                Arguments.of(
                        "Combination: mandatory claims — name, address, nationalities, birth_year",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsFixtures.mandatory()
                ),

                Arguments.of(
                        "Combination: full disclosure of all claims",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsFixtures.all()
                ),

                Arguments.of(
                        "Combination: string scalar + string array + object array nested field",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("name")
                                .arrayAll("nationalities")
                                .arrayField("degrees", "type")
                                .build()
                ),

                Arguments.of(
                        "Combination: number scalar + image scalar + number array",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("birth_year")
                                .claim("portrait")
                                .arrayAll("favorite_numbers")
                                .build()
                )
        );
    }

    static Stream<Arguments> sdJwtSelectiveDisclosureScenariosFailure() {
        return Stream.of(

                // Value mismatch: string scalar --

                Arguments.of(
                        "String scalar mismatch: 'name' disclosed, verifier expects 'Jane Doe', VC has 'John Doe'",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("name", List.of("Jane Doe"))
                                .build()
                ),

                Arguments.of(
                        "String scalar mismatch: 'additional_info' disclosed, verifier expects 'other-value', VC has 'some-random-value'",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("additional_info", List.of("other-value"))
                                .build()
                ),

                // Value mismatch: number scalar --

                Arguments.of(
                        "Number scalar mismatch: 'birth_year' disclosed, verifier expects 2000, VC has 1978",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("birth_year", List.of(2000))
                                .build()
                ),

                // Value mismatch: image (string) scalar --

                Arguments.of(
                        "Image scalar mismatch: 'portrait' disclosed, verifier expects wrong URL, VC has correct URL",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("portrait", List.of("https://example.com/images/other.png"))
                                .build()
                ),

                // Value mismatch: string array --

                Arguments.of(
                        "String array mismatch: 'nationalities' all disclosed, verifier expects ['French'], VC has ['British', 'Betelgeusian']",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayAllWithValues("nationalities", List.of("French"))
                                .build()
                ),

                // Value mismatch: number array --

                Arguments.of(
                        "Number array mismatch: 'favorite_numbers' all disclosed, verifier expects [99], VC has [3, 7, 42]",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayAllWithValues("favorite_numbers", List.of(99))
                                .build()
                ),

                // Value mismatch: mixed-type array --

                Arguments.of(
                        "Mixed-type array mismatch: 'additional_info_list' has 3 strings + 2 numbers, verifier expects number 99 which is absent",
                        CredentialClaimsBuilder.base()
                                .withArray("additional_info_list", List.of("alpha", "beta", "gamma", 7, 42))
                                .build(),
                        VerificationClaimsBuilder.claims()
                                .arrayAllWithValues("additional_info_list", List.of(99))
                                .build()
                ),

                // Value mismatch: object array nested field --

                Arguments.of(
                        "Object array mismatch: 'degrees[*].type' disclosed, verifier expects ['PhD'], VC has [Bachelor, Master]",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayField("degrees", "type", List.of("PhD"))
                                .build()
                ),

                Arguments.of(
                        "Object array mismatch: 'degrees[*].university' disclosed, verifier expects ['MIT'], VC has ['University of Betelgeuse']",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayField("degrees", "university", List.of("MIT"))
                                .build()
                ),

                // Value mismatch: object nested field --

                Arguments.of(
                        "Object mismatch: 'address.locality' disclosed, verifier expects 'Zurich', VC has 'Milliways'",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .nestedWithValues(List.of("Zurich"), "address", "locality")
                                .build()
                )
        );
    }

    static Stream<Arguments> sdJwtSelectiveDisclosureScenariosNoneExistantFailure() {
        return Stream.of(

                Arguments.of(
                        "Full VP (no SD): verifier requests 'degrees[*].type = NonExisting', credential has Bachelor/Master",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsFixtures.nonMatchingValue()
                ),

                Arguments.of(
                        "Full VP (no SD): verifier requests 'name = Jane Doe', credential has 'John Doe'",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("name", List.of("Jane Doe"))
                                .build()
                ),

                Arguments.of(
                        "Full VP (no SD): verifier requests 'birth_year = 2000', credential has 1978",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("birth_year", List.of(2000))
                                .build()
                ),

                Arguments.of(
                        "Full VP (no SD): verifier requests 'portrait = wrong URL', credential has correct URL",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("portrait", List.of("https://example.com/images/other.png"))
                                .build()
                ),

                Arguments.of(
                        "Full VP (no SD): verifier requests non-existent top-level claim 'unknown_field'",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("unknown_field")
                                .build()
                ),

                Arguments.of(
                        "Full VP (no SD): verifier requests multiple non-matching degree types ['A','B','C']",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayField("degrees", "type", List.of("A", "B", "C"))
                                .build()
                )
            );
    }

    @ParameterizedTest
    @MethodSource("sdJwtSelectiveDisclosureScenariosSuccessful")
    @XrayTest(
            key = "EIDOMNI-832",
            summary = "Selective disclosure of SD-JWT credential succeeds for all supported claim types",
            description = """
                    This test validates that selective disclosure works correctly for string, number, image, object, and array claim types. \
                    The wallet builds a derived VP containing only the requested disclosures and submits it to the verifier. \
                    The verifier accepts the presentation because all disclosed values satisfy the requested constraints.\
                    """)
    @Tag(ReportingTags.UCI_C1A)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.HAPPY_PATH)
    void boundNonDeferredCredential_whenIssuedWithArrayDisclosureAndVerified_thenSuccess(final String assertMessage, final Map<String, Object> subjectClaims, final List<DcqlClaimDto> verificationClaims) {
        // Given
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_IDENTITY_PROFILE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId, subjectClaims);
        final WalletBatchEntry entry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        // Then
        SdJwtBatchAssert.assertThat(entry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique();

        // When
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withDCQL(verificationClaims)
                .createManagementResponse();
        final RequestObject verificationDetails = wallet
                .getVerificationDetailsUnsigned(verification.getVerificationDeeplink());

        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

        log.info("DATA");
        log.info("VC Claims: {}", subjectClaims);

        final String presentation = entry.createSelectiveDisclosurePresentationForSdJwtIndex(0, verificationDetails);
        log.info("Test: {}", assertMessage);
        log.info("DCQL: {}", verificationDetails.getDcqlQuery().getCredentials().getFirst().getClaims());
        log.info("VC: {}", entry.getIssuedCredentials().get(0));
        log.info("VP: {}", presentation);
        wallet.respondToVerificationV1(verificationDetails, presentation);

        // Thenm6m
        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS, assertMessage);
    }

    @ParameterizedTest
    @MethodSource("sdJwtSelectiveDisclosureScenariosFailure")
    @XrayTest(
            key = "EIDOMNI-888",
            summary = "Selective disclosure rejected when disclosed values do not match verifier constraints",
            description = """
                    This test validates that the verifier rejects a selectively disclosed VP when the disclosed claim values do not satisfy the requested constraints. \
                    The wallet correctly builds a selective disclosure presentation, but the values in the VC differ from what the verifier expects. \
                    The verifier responds with a 400 error indicating that not all requested claim values are satisfied.\
                    """)
    @Tag(ReportingTags.UCI_C1A)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.UCV_O2)
    @Tag(ReportingTags.EDGE_CASE)
    void boundNonDeferredCredential_whenIssuedWithArrayDisclosureAndVerified_thenRejected(final String assertMessage, final Map<String, Object> subjectClaims, final List<DcqlClaimDto> verificationClaims) {
        // Given
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_IDENTITY_PROFILE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId, subjectClaims);
        final WalletBatchEntry entry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        // Then
        SdJwtBatchAssert.assertThat(entry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique();

        // When
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withDCQL(verificationClaims)
                .createManagementResponse();
        final RequestObject verificationDetails = wallet
                .getVerificationDetailsUnsigned(verification.getVerificationDeeplink());

        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

        log.info("DATA");
        log.info("VC Claims: {}", subjectClaims);

        final String presentation = entry.createSelectiveDisclosurePresentationForSdJwtIndex(0, verificationDetails);
        log.info("Test: {}", assertMessage);
        log.info("DCQL: {}", verificationDetails.getDcqlQuery().getCredentials().getFirst().getClaims());
        log.info("VC: {}", entry.getIssuedCredentials().get(0));
        log.info("VP: {}", presentation);
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class,
                () -> wallet.respondToVerificationV1(verificationDetails, presentation),
                assertMessage);

        // Then
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasErrorDescription("Not all requested claim values are satisfied");

        // Then
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
    }

    @ParameterizedTest
    @MethodSource("sdJwtSelectiveDisclosureScenariosNoneExistantFailure")
    @XrayTest(
            key = "EIDOMNI-889",
            summary = "Rejection of invalid array disclosure verification requests",
            description = """
                    This test validates that array disclosure verification correctly rejects invalid requests.
                    Scenarios cover: non-matching values, non-existent array indices, and non-existent claim paths.
                    The wallet issues a credential but the verification request cannot be satisfied, resulting in rejection.
                    """)
    @Tag(ReportingTags.UCI_C1A)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.UCV_O2)
    void boundNonDeferredCredential_whenIssuedAndVPCompleteProfileVerified_thenRejected(final String assertMessage,
                                                                            final Map<String,
            Object> subjectClaims, final List<DcqlClaimDto> verificationClaims) {
        // Given
        final String supportedMetadataId = CredentialConfigurationFixtures.BOUND_IDENTITY_PROFILE_SD_JWT;

        // When
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(supportedMetadataId, subjectClaims);
        final WalletBatchEntry entry = wallet.collectOffer(toUri(offer.getOfferDeeplink()));

        // Then
        SdJwtBatchAssert.assertThat(entry.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique();

        // When
        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withDCQL(verificationClaims)
                .createManagementResponse();
        final RequestObject verificationDetails = wallet
                .getVerificationDetailsUnsigned(verification.getVerificationDeeplink());

        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);

        log.info("DATA");
        log.info("VC Claims: {}", subjectClaims);

        final String presentation = entry.createPresentationForSdJwtIndex(0, verificationDetails);
        log.info("Test: {}", assertMessage);
        log.info("DCQL: {}", verificationDetails.getDcqlQuery().getCredentials().getFirst().getClaims());
        log.info("VC: {}", entry.getIssuedCredentials().get(0));
        log.info("VP: {}", presentation);
        final HttpClientErrorException ex = assertThrows(HttpClientErrorException.class,
                () -> wallet.respondToVerificationV1(verificationDetails, presentation),
                assertMessage);

        // Then
        ApiErrorAssert.assertThat(ex)
                .hasStatus(400)
                .hasErrorDescription(List.of("Not all requested claim values are satisfied", "Requested DCQL path could not be found"));

        // Then
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
    }
}
