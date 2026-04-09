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

                Arguments.of(
                        "Mandatory claims only",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsFixtures.mandatory()
                ),

                Arguments.of(
                        "Full disclosure of all claims",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsFixtures.all()
                ),

                Arguments.of(
                        "Disclose all elements from array (degrees)",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayAll("degrees")
                                .build()
                ),

                Arguments.of(
                        "Disclose specific index in array",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayIndex("degrees", 0)
                                .build()
                ),

                Arguments.of(
                        "Disclose nested field from all objects in array",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayField("degrees", "type")
                                .build()
                ),

                Arguments.of(
                        "Disclose array field with matching value",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayField("degrees", "type", List.of("Bachelor of Science"))
                                .build()
                ),

                Arguments.of(
                        "Mixed claims: simple + array + nested",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("name")
                                .arrayAll("nationalities")
                                .arrayField("degrees", "type")
                                .build()
                ),

                Arguments.of(
                        "Optional claim disclosure",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("portrait")
                                .build()
                ),

                Arguments.of(
                        "Numeric array disclosure",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayAll("favorite_numbers")
                                .build()
                ),

                Arguments.of(
                        "Mixed type array disclosure",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayAll("additional_info_list")
                                .build()
                )
        );
    }

    static Stream<Arguments> sdJwtSelectiveDisclosureScenariosFailure() {
        return Stream.of(

                Arguments.of(
                        "Value mismatch in array",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayField("degrees", "type", List.of("NonExisting"))
                                .build()
                ),

                Arguments.of(
                        "Non-existent claim",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .claim("unknown_field")
                                .build()
                ),

                Arguments.of(
                        "Non-existent nested field",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .nested("degrees", null, "unknown")
                                .build()
                ),

                Arguments.of(
                        "Out of bounds array index",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayIndex("degrees", 99)
                                .build()
                ),

                Arguments.of(
                        "Invalid deep nested path",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .nested("address", "invalid_field")
                                .build()
                ),

                Arguments.of(
                        "Numeric value mismatch",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayAll("favorite_numbers")
                                .build() // verifier expects values but none match internally scenario
                ),

                Arguments.of(
                        "Multiple non-matching values in array",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayField("degrees", "type", List.of("A", "B", "C"))
                                .build()
                ),

                Arguments.of(
                        "Request array on non-array field",
                        CredentialClaimsFixtures.createBaseProfile(),
                        VerificationClaimsBuilder.claims()
                                .arrayAll("name") // invalid type
                                .build()
                ),

                Arguments.of(
                        "Invalid null usage in non-array path",
                        CredentialClaimsFixtures.createBaseProfile(),
                        List.of(
                                new DcqlClaimDto()
                                        .path(List.of("name", null))
                                        .id(null)
                                        .values(null)
                        )
                )
        );
    }

    @ParameterizedTest
    @MethodSource("sdJwtSelectiveDisclosureScenariosSuccessful")
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Successful issuance and verification of bound SD-JWT with array disclosure",
            description = """
                    This test validates the end-to-end issuance and verification of a bound SD-JWT credential
                    containing array disclosure claims (array_mandatory, array_optional).
                    Multiple scenarios test different array disclosure patterns: full disclosure, value matching,
                    index-based selection, and mixed data type handling.
                    The wallet collects the non-deferred credential and presents it to a verifier for validation.
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
        log.info("Verification Claims: {}", verificationDetails.getDcqlQuery().getCredentials().getFirst().getClaims());

        final String presentation = entry.createSelectiveDisclosurePresentationForSdJwtIndex(0, verificationDetails);
        wallet.respondToVerificationV1(verificationDetails, presentation);

        // Then
        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS, assertMessage);
    }

    @ParameterizedTest
    @MethodSource("sdJwtSelectiveDisclosureScenariosFailure")
    @XrayTest(
            key = "EIDOMNI-XXX",
            summary = "Rejection of invalid array disclosure verification requests",
            description = """
                    This test validates that array disclosure verification correctly rejects invalid requests.
                    Scenarios cover: non-matching values, non-existent array indices, and non-existent claim paths.
                    The wallet issues a credential but the verification request cannot be satisfied, resulting in rejection.
                    """)
    @Tag(ReportingTags.UCI_C1A)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.UCV_O2)
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
        log.info("Verification Claims: {}", verificationDetails.getDcqlQuery().getCredentials().getFirst().getClaims());

        final String presentation = entry.createSelectiveDisclosurePresentationForSdJwtIndex(0, verificationDetails);
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
}
