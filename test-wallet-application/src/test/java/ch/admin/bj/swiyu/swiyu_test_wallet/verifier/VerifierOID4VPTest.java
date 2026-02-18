package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JwtSupport;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierOID4VPTest extends BaseTest {
    @Test
    @XrayTest(
            key = "EIDOMNI-554",
            summary = "Wallet retrieves a signed OID4VP request object from verifier",
            description = """
                    This test validates that the wallet can successfully retrieve a signed OpenID Connect
                    request object from the verifier containing verification query details, response information,
                    and cryptographic parameters required for the OID4VP flow.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1A)
    @Tag(ReportingTags.HAPPY_PATH)
    void walletFetchesSignedRequestObject_thenSuccess() {

        // GIVEN – verifier initiates verification (UCV_M1)
        final VerifierManager.VerificationRequestBuilder verifierManagerRequest = verifierManager
                .verificationRequest(true)
                .acceptedIssuerDid("did:swiyu:university")
                .withUniversity()
                .jwtSecure();
        final ManagementResponse managementResponse = verifierManagerRequest.createManagementResponse();

        // WHEN – wallet fetches request object (OID4VP)
        final String requestObjectJwt =
                wallet.getVerificationDetailSigned(managementResponse.getVerificationDeeplink());
        final JsonNode payload = JwtSupport.decodePayloadToJsonNode(requestObjectJwt);

        // THEN – signed request object (UCV_O1a)
        assertThat(requestObjectJwt)
                .as("OID4VP request object must be returned by the verifier")
                .isNotNull()
                .as("OID4VP request object must be returned as a compact JWT")
                .isNotBlank();

        assertThat(JwtSupport.isCompactJwt(requestObjectJwt))
                .as("OID4VP request object must be a compact JWS (header.payload.signature)")
                .isTrue();

        assertThat(payload.get("client_id"))
                .as("Request object must contain client_id")
                .isNotNull();

        assertThat(payload.get("client_id_scheme").asText())
                .as("Request object must contain did client_id_scheme")
                .isEqualTo("did");

        assertThat(payload.get("response_uri").asText())
                .as("Request object must contain response_uri")
                .isNotNull();

        assertThat(payload.get("response_uri").asText())
                .as("response_uri must point to the verifier OID4VP response endpoint")
                .contains(String.format("/oid4vp/api/request-object/%s/response-data", managementResponse.getId()));

        assertThat(payload.get("response_mode"))
                .as("Request object must define response_mode")
                .isNotNull();

        assertThat(payload.get("response_mode").asText())
                .as("response_mode must match verifier response mode configuration")
                .isEqualTo(
                        verifierManagerRequest.getRequest().getResponseMode().getValue()
                );

        assertThat(payload.get("nonce"))
                .as("Request object must contain a nonce")
                .isNotNull();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-555",
            summary = "Wallet retrieves an unsigned OID4VP request object from verifier",
            description = """
                    This test validates that the wallet can successfully retrieve an unsigned OpenID Connect
                    request object from the verifier containing DCQL-based verification query details, encrypted
                    response requirements, and necessary cryptographic parameters for the OID4VP flow.
                    """
    )
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1B)
    @Tag(ReportingTags.HAPPY_PATH)
    void walletFetchesUnsignedRequestObject_thenSuccess() {

        // GIVEN – verifier initiates verification (UCV_M1)
        final VerifierManager.VerificationRequestBuilder verifierManagerRequest = verifierManager
                .verificationRequest(false)
                .acceptedIssuerDid("did:swiyu:university")
                .withUniversityDCQL()
                .encrypted()
                .jwtUnsecure();
        final ManagementResponse managementResponse = verifierManagerRequest.createManagementResponse();

        // WHEN – wallet fetches request object (OID4VP)
        final RequestObject requestObject =
                wallet.getVerificationDetailsUnsigned(managementResponse.getVerificationDeeplink());

        // THEN – signed request object (UCV_O1a)
        assertThat(requestObject)
                .as("OID4VP request object must be returned by the verifier")
                .isNotNull();

        assertThat(requestObject.getClientId())
                .as("Request object must contain client_id")
                .isNotNull();

        assertThat(requestObject.getClientIdScheme())
                .as("Request object must contain did client_id_scheme")
                .isEqualTo("did");

        assertThat(requestObject.getResponseUri())
                .as("Request object must contain response_uri")
                .isNotNull();

        assertThat(requestObject.getResponseUri())
                .as("response_uri must point to the verifier OID4VP response endpoint")
                .contains(String.format("/oid4vp/api/request-object/%s/response-data", managementResponse.getId()));

        assertThat(requestObject.getResponseMode())
                .as("Request object must define response_mode")
                .isNotNull();

        assertThat(requestObject.getResponseMode().getValue())
                .as("response_mode must match verifier response mode configuration")
                .isEqualTo(verifierManagerRequest.getRequest().getResponseMode().getValue());

        assertThat(requestObject.getNonce())
                .as("Request object must contain a nonce")
                .isNotNull();
    }

}
