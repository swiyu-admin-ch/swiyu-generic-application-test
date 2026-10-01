package ch.admin.bj.swiyu.swiyu_test_wallet.mock;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.TrustConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.HttpRequest;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.json.JsonMapper;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;

/**
 * The trust service of the first generation: {@code GET .../api/v1/truststatements/issuance} returns the issuance trust
 * statements ({@code TrustStatementIssuanceV1}, one per registered issuer) for a {@code vct}. Trust Protocol 2.0 is served by
 * {@code mock.tp2}.
 */
@Slf4j
final class LegacyTrustStatements {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .disable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    private final RegisteredActors actors;

    LegacyTrustStatements(final RegisteredActors actors) {
        this.actors = actors;
    }

    void registerRoutes(final MockServerClient mockServerClient) {
        mockServerClient.when(
                        request()
                                .withMethod("GET")
                                .withPath(".*/api/v1/truststatements/issuance")
                )
                .respond(httpRequest -> {
                    try {
                        String path = httpRequest.getPath().getValue();
                        String vct = firstPresentQueryParameter(httpRequest, "vcSchemaId", "schemaId", "vct");

                        if (path.startsWith("/trusted/")) {
                            final List<String> trustStatements = new ArrayList<>();
                            for (IssuerConfig issuerConfig : actors.issuers()) {
                                trustStatements.add(issuanceStatement(vct, issuerConfig, actors.trustConfig()));
                            }

                            return response()
                                    .withStatusCode(200)
                                    .withHeader(CONTENT_TYPE, "application/json")
                                    .withBody(OBJECT_MAPPER.writeValueAsString(trustStatements));
                        }
                        return response()
                                .withStatusCode(200)
                                .withHeader(CONTENT_TYPE, "application/json")
                                .withBody("[]");
                    } catch (Exception e) {
                        return response().withStatusCode(500);
                    }
                });
    }

    String issuanceStatement(final String vct, final IssuerConfig issuerConfig) throws JOSEException {
        return issuanceStatement(vct, issuerConfig, actors.trustConfig());
    }

    private static String firstPresentQueryParameter(final HttpRequest httpRequest, final String... names) {
        for (String name : names) {
            String value = httpRequest.getFirstQueryStringParameter(name);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private static String issuanceStatement(final String vct, final IssuerConfig issuerConfig, final TrustConfig trustConfig)
            throws JOSEException {

        if (trustConfig.getTrustAssertKeyPemString() == null || trustConfig.getTrustAssertKeyPemString().isEmpty()) {
            log.error("Trust key PEM not available, cannot generate trust statement");
            throw new JOSEException("Trust key is not available");
        }

        final JWK trustJwk = JWK.parseFromPEMEncodedObjects(trustConfig.getTrustAssertKeyPemString());
        final JWSSigner signer = new ECDSASigner(trustJwk.toECKey());

        final String issuerDid = issuerConfig.getIssuerDid();

        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(trustConfig.getTrustDid())
                .subject(issuerDid)
                .claim("vct", "TrustStatementIssuanceV1")
                .claim("canIssue", vct)
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                .build();

        final SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .keyID(trustConfig.getTrustAssertKeyId())
                        .type(new JOSEObjectType("vc+sd-jwt"))
                        .build(),
                claimsSet);

        signedJWT.sign(signer);

        return signedJWT.serialize() + "~";
    }
}
