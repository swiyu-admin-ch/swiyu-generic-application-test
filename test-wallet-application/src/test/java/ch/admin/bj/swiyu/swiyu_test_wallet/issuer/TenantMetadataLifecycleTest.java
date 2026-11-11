package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.SwiyuDeeplink;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.UseWallet;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

/** Covers the tenant metadata retirement policy introduced by EIDOMNI-1323. */
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.COMPLETE)
@UseWallet(dpop = true, encryption = true, signedMetadata = true)
class TenantMetadataLifecycleTest extends BaseTest {

    @ParameterizedTest(name = "family={0}, offer={1}, metadata retired={2}")
    @CsvSource({"EXPIRED, EXPIRED, true", "CANCELLED, CANCELLED, true",
            "ISSUED, ISSUED, false", "REVOKED, ISSUED, false"})
    @XrayTest(key = "EIDOMNI-1557",
            summary = "Credential Issuer retires expired or cancelled tenant metadata and preserves issued metadata",
            description = """
                    Given an active offer whose tenant returns valid signed Credential Issuer Metadata.
                    When the offer expires, is cancelled, is issued, or its issued family is revoked.
                    Then expired and cancelled offers return HTTP 410 while issued offers still return valid signed metadata.
                    Revoking an issued family keeps its tenant metadata available; repeated reads leave management unchanged.
                    Spec: EIDOMNI-1323 product policy; RFC 9110 section 15.5.11; OID4VCI 1.0 section 12.2.3.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCI_M1_PROVIDE_METADATA_RELATED_TO_VCS)
    @Tag(ReportingTags.UCI_W1_EXPOSE_OPENID_WELL_KNOWN_ENDPOINTS)
    void signedMetadata_whenOfferBecomesTerminal_thenRetirementPolicyPreservesTheFamily(
            final String lifecycle, final String expectedOfferStatus, final boolean retired) throws Exception {
        assumeFalse(retired, "EIDOMNI-1323: awaiting the tenant metadata retirement concept; "
                + "the issuer still returns HTTP 500 instead of 410 for expired or cancelled offers.");

        // Given: the same tenant and signing key work before the terminal transition.
        final var offer = issuerManager.createCredentialOffer(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT);
        final String issuer = new SwiyuDeeplink(offer.getOfferDeeplink()).getCredentialIssuer();
        final URI metadataUri = UriComponentsBuilder
                .fromUri(wallet.getIssuerContext().getContextualizedUri(URI.create(issuer)))
                .pathSegment(".well-known", "openid-credential-issuer")
                .build().toUri();
        final var signatureVerifier = new ECDSAVerifier((ECPublicKey) issuerConfig.getKeyPair().getPublic());
        final var activeResponse = restClient.get().uri(metadataUri)
                .header(HttpHeaders.ACCEPT, "application/jwt").retrieve().toEntity(String.class);
        assertThat(activeResponse.getStatusCode().value())
                .isEqualTo(200);
        final var metadata = SignedJWT.parse(activeResponse.getBody());
        assertThat(metadata.verify(signatureVerifier))
                .isTrue();
        assertThat(metadata.getJWTClaimsSet().getSubject())
                .isEqualTo(issuer);

        // When: use real issuance/revocation; the test database prepares expiry and offer-only cancellation.
        final String schema = currentIssuer.imageConfig().getDbSchema();
        switch (lifecycle) {
            case "EXPIRED" -> {
                try (var update = connection.prepareStatement("UPDATE " + schema
                        + ".credential_offer SET offer_expiration_timestamp = ? WHERE id = ? AND credential_management_id = ?")) {
                    update.setLong(1, Instant.now().minusSeconds(1).getEpochSecond());
                    update.setObject(2, offer.getOfferId());
                    update.setObject(3, offer.getManagementId());
                    assertThat(update.executeUpdate())
                            .isEqualTo(1);
                }
                issuerManager.getCredentialById(offer.getManagementId());
            }
            case "CANCELLED" -> {
                try (var update = connection.prepareStatement("UPDATE " + schema
                        + ".credential_offer SET credential_status = 'CANCELLED' WHERE id = ? AND credential_management_id = ?")) {
                    update.setObject(1, offer.getOfferId());
                    update.setObject(2, offer.getManagementId());
                    assertThat(update.executeUpdate())
                            .isEqualTo(1);
                }
            }
            case "ISSUED", "REVOKED" -> {
                final var batch = wallet.collectOffer(toUri(offer.getOfferDeeplink()));
                assertThat(batch.getIssuedCredentials())
                        .hasSize(CredentialConfigurationFixtures.BATCH_SIZE);
                if ("REVOKED".equals(lifecycle)) {
                    issuerManager.updateState(offer.getManagementId(), UpdateCredentialStatusRequestType.REVOKED);
                }
                assertThat(issuerManager.getStatusById(offer.getManagementId()).getStatus())
                        .isEqualTo(CredentialStatusType.valueOf(lifecycle));
            }
            default -> throw new IllegalArgumentException("Unknown test lifecycle: " + lifecycle);
        }
        try (var query = connection.prepareStatement("SELECT credential_status FROM " + schema
                + ".credential_offer WHERE id = ? AND credential_management_id = ?")) {
            query.setObject(1, offer.getOfferId());
            query.setObject(2, offer.getManagementId());
            try (var rows = query.executeQuery()) {
                assertThat(rows.next())
                        .isTrue();
                assertThat(rows.getString(1))
                        .isEqualTo(expectedOfferStatus);
            }
        }
        final var beforeLookup = issuerManager.getCredentialById(offer.getManagementId());

        // Then: retirement depends on the offer state, not the family's revocation state.
        for (int attempt = 0; attempt < 3; attempt++) {
            if (retired) {
                final var failure = assertThrows(RestClientResponseException.class,
                        () -> restClient.get().uri(metadataUri).header(HttpHeaders.ACCEPT, "application/jwt")
                                .retrieve().toEntity(String.class));
                assertThat(failure.getStatusCode().value())
                        .isEqualTo(410);
            } else {
                final var response = restClient.get().uri(metadataUri).header(HttpHeaders.ACCEPT, "application/jwt")
                        .retrieve().toEntity(String.class);
                assertThat(response.getStatusCode().value())
                        .isEqualTo(200);
                final var currentMetadata = SignedJWT.parse(response.getBody());
                assertThat(currentMetadata.verify(signatureVerifier))
                        .isTrue();
                assertThat(currentMetadata.getJWTClaimsSet().getSubject())
                        .isEqualTo(issuer);
            }
        }
        assertThat(issuerManager.getCredentialById(offer.getManagementId()))
                .usingRecursiveComparison()
                .isEqualTo(beforeLookup);
    }
}
