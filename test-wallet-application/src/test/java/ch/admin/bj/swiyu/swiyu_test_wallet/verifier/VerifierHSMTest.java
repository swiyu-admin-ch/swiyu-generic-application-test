package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.verifier.model.ConfigurationOverrideDto;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@ActiveProfiles({"issuer-hsm", "verifier-hsm"})
@EnabledIfSystemProperty(
        named = "hsm",
        matches = "true",
        disabledReason = "HSM tests require -Dhsm=true so SoftHSM is injected only when explicitly requested."
)
class VerifierHSMTest extends BaseTest {

    private static final String DEFAULT_HSM_KEY_ID = "01";
    private static final String OVERRIDE_HSM_KEY_ID = "02";

    @Test
    @XrayTest(
            key = "EIDOMNI-967",
            summary = "Verifier signs request object with override HSM key id without key pin",
            description = """
                    This test validates that the Business Verifier management API honors a ConfigurationOverride
                    containing only key_id when signing a JWT-secured OID4VP request object, using the default HSM
                    key PIN and the override key instead of the configured default HSM key.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1A)
    @Tag(ReportingTags.EDGE_CASE)
    void signedRequestObject_withOnlyOverrideHsmKeyId_thenUsesOverrideKey() throws Exception {
        // Given
        final ConfigurationOverrideDto configurationOverride = new ConfigurationOverrideDto()
                .verificationMethod(issuerConfig.getIssuerAuthKeyId())
                .keyId(OVERRIDE_HSM_KEY_ID);

        assertThat(configurationOverride.getKeyPin())
                .as("The regression scenario must provide only key_id in ConfigurationOverride")
                .isNull();

        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withUniversityDCQL()
                .jwtSecure()
                .configurationOverride(configurationOverride)
                .createManagementResponse();

        // When
        final SignedJWT requestObject = SignedJWT.parse(
                wallet.getVerificationDetailSigned(verification.getVerificationDeeplink())
        );

        // Then
        assertThat(requestObject.getHeader().getKeyID())
                .as("The signed request object must advertise the configured verifier verification method")
                .isEqualTo(issuerConfig.getIssuerAuthKeyId());
        assertThat(isSignedByHsmKey(requestObject, OVERRIDE_HSM_KEY_ID))
                .as("The request object should be signed with the HSM key from ConfigurationOverride.key_id")
                .isTrue();
        assertThat(isSignedByHsmKey(requestObject, DEFAULT_HSM_KEY_ID))
                .as("The request object should not fall back to the verifier's default HSM key")
                .isFalse();
    }

    private boolean isSignedByHsmKey(final SignedJWT jwt, final String keyId) throws Exception {
        final String certificateResourcePath = "softhsm/keys/%s-cert.pem".formatted(keyId);
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(certificateResourcePath)) {
            assertThat(inputStream)
                    .as("HSM public certificate should be available: %s", certificateResourcePath)
                    .isNotNull();
            final String certificatePem = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
            return jwt.verify(new ECDSAVerifier(JWK.parseFromPEMEncodedX509Cert(certificatePem).toECKey()));
        }
    }
}
