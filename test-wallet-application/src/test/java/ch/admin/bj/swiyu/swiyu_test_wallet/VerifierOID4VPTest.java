package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JwtSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class VerifierOID4VPTest extends BaseTest {
    @Test
    @XrayTest(
            key = "EIDOMNI-554",
            summary = "Wallet retrieves a signed OID4VP request object from verifier",
            description = """
                    Validate that the verifier exposes a signed OpenID Connect
                    request object containing the verification query and response information.
                    """
    )
    @Tag("ucv_o1")
    @Tag("ucv_o1a")
    @Tag("happy_path")
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
                .isNotNull();

        assertThat(requestObjectJwt)
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
            summary = "Wallet retrieves a signed OID4VP request object from verifier",
            description = """
                    Validate that the verifier exposes a signed OpenID Connect
                    request object containing the verification query and response information.
                    """
    )
    @Tag("ucv_o1")
    @Tag("ucv_o1b")
    @Tag("happy_path")
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
