package ch.admin.bj.swiyu.swiyu_test_wallet.security;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseVerifiers;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JwtSupport;
import tools.jackson.databind.JsonNode;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.time.Duration;
import java.time.Instant;

import static ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant.SHORT_LIVED_REQUEST_OBJECT_TTL_SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseVerifiers(VerifierVariant.SHORT_LIVED_REQUEST_OBJECT)
class RequestObjectReplayProtectionTest extends BaseTest {

    @Test
    @XrayTest(
            key = "EIDOMNI-1199",
            summary = "Signed Request Object has a configurable short validity window",
            description = """
                    This test verifies that the signed OID4VP Request Object contains iat and exp as Unix Epoch
                    timestamps, that their difference reflects the configured validity duration, and that a captured
                    Request Object becomes expired without changing the pending verification transaction.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1A)
    @Tag(ReportingTags.EDGE_CASE)
    void signedRequestObject_whenValidityWindowElapses_thenCapturedObjectIsExpired() {
        // Given - the verifier is configured with a short Request Object validity duration
        final ManagementResponse verification = verifierManager
                .verificationRequest(true)
                .acceptedIssuerDid("did:swiyu:university")
                .withUniversityDCQL()
                .jwtSecure()
                .createManagementResponse();
        final long beforeRetrievalEpochSecond = Instant.now().getEpochSecond();

        // When - the wallet retrieves the signed Request Object
        final String requestObjectJwt = wallet.getVerificationDetailSigned(verification.getVerificationDeeplink());
        final long afterRetrievalEpochSecond = Instant.now().getEpochSecond();
        final JsonNode payload = JwtSupport.decodePayloadToJsonNode(requestObjectJwt);

        // Then - iat and exp are UTC-independent Epoch seconds with the configured validity window
        assertThat(payload.path("iat").isIntegralNumber())
                .as("iat must be encoded as Unix Epoch Time in whole seconds")
                .isTrue();
        assertThat(payload.path("exp").isIntegralNumber())
                .as("exp must be encoded as Unix Epoch Time in whole seconds")
                .isTrue();

        final long issuedAtEpochSecond = payload.path("iat").longValue();
        final long expiresAtEpochSecond = payload.path("exp").longValue();

        assertThat(issuedAtEpochSecond)
                .as("iat must represent the Request Object creation time")
                .isBetween(beforeRetrievalEpochSecond, afterRetrievalEpochSecond);
        assertThat(expiresAtEpochSecond)
                .as("exp must be later than iat")
                .isGreaterThan(issuedAtEpochSecond);
        assertThat(expiresAtEpochSecond - issuedAtEpochSecond)
                .as("Request Object validity must reflect the configured TTL")
                .isBetween(
                        (long) SHORT_LIVED_REQUEST_OBJECT_TTL_SECONDS,
                        (long) SHORT_LIVED_REQUEST_OBJECT_TTL_SECONDS + 1
                );

        await()
                .atMost(Duration.ofSeconds(SHORT_LIVED_REQUEST_OBJECT_TTL_SECONDS + 3L))
                .untilAsserted(() -> assertThat(Instant.now().getEpochSecond())
                        .as("the clock must pass exp before the captured Request Object is considered expired")
                        .isGreaterThan(expiresAtEpochSecond));

        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
    }
}
