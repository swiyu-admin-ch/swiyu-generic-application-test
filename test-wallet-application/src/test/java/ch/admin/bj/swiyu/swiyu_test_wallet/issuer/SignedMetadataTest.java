package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.IssuerMetadata;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.SwiyuDeeplink;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.stream.Stream;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class SignedMetadataTest extends BaseTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();


    @BeforeEach
    void beforeEach() {
        wallet.setSignedMetadataPreferred(true);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-402",
            summary = "Validate retrieval and verification of signed issuer metadata (happy path)",
            description = """
                    This test validates that a wallet can successfully request, retrieve, and verify signed issuer metadata
                    according to the OID4VCI specification when the signed metadata feature is enabled on the issuer.
                    The wallet decodes the signed JWT response and confirms that all required OID4VCI metadata claims are present.
                    """
    )
    @Tag(ReportingTags.UCI_M1)
    @Tag(ReportingTags.UCI_M1A)
    @Tag(ReportingTags.HAPPY_PATH)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void shouldSuccessfullyValidateSignedMetadata() {
        var walletEntry = wallet.createWalletBatchEntry();
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final String deeplink = response.getOfferDeeplink();

        final SwiyuDeeplink swiyuDeeplink = new SwiyuDeeplink(deeplink);

        walletEntry.receiveDeepLinkAndValidateIt(URI.create(deeplink));

        walletEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(walletEntry));
        walletEntry.setToken(wallet.collectToken(walletEntry));

        final IssuerMetadata metadata = wallet.getIssuerWellKnownMetadata(walletEntry);

        assertThat(metadata).isNotNull();

        final JsonNode metadataRaw = walletEntry.getIssuerMetadataRaw();

        if (metadataRaw.has("iss")) {
            assertThat(metadataRaw.get("iss").asText())
                    .isEqualTo(issuerConfig.getIssuerDid());
        }

        assertThat(metadataRaw.get("sub").asText())
                .isEqualTo(swiyuDeeplink.getCredentialIssuer());

        assertThat(metadataRaw.has("iat"))
                .isTrue();
        assertThat(metadataRaw.get("iat").asLong())
                .isPositive();

        if (metadataRaw.has("exp")) {
            assertThat(metadataRaw.get("exp").asLong())
                    .isGreaterThan(metadataRaw.get("iat").asLong());
        }
    }

    @ParameterizedTest(name = "[{index}] Accept={0}")
    @MethodSource("signedMetadataAcceptHeaderCases")
    @XrayTest(
            key = "EIDOMNI-942",
            summary = "Issuer parses Accept header correctly for signed issuer metadata",
            description = """
                    This test validates that the tenant-specific issuer metadata endpoint parses the wallet Accept
                    header correctly for signed metadata requests, including case-insensitive media types and quality
                    values that make application/jwt unacceptable.
                    """
    )
    @Tag(ReportingTags.UCI_M1)
    @Tag(ReportingTags.UCI_M1A)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void signedMetadata_whenAcceptHeaderVaries_thenIssuerChoosesCorrectRepresentation(
            String acceptHeader,
            MediaType expectedContentType,
            boolean expectedJwtResponse
    ) throws Exception {
        final URI metadataUri = createTenantSpecificWellKnownUri("/.well-known/openid-credential-issuer");
        final ResponseEntity<String> response = performMetadataRequest(metadataUri, acceptHeader);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getHeaders().getContentType()).satisfies(contentType ->
                assertThat(contentType).isNotNull().matches(expectedContentType::includes));

        if (expectedJwtResponse) {
            assertThat(SignedJWT.parse(response.getBody())).isNotNull();
            return;
        }

        assertThat(response.getBody()).startsWith("{");
        assertThat(walletEntryJson(response.getBody()).has("credential_endpoint")).isTrue();
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-740",
            summary = "Validate retrieval of unsigned issuer metadata with tenantId (happy path)",
            description = """
                    This test validates that a wallet can successfully request and retrieve unsigned issuer metadata
                    when the signed metadata feature is disabled and a tenantId is used.
                    
                    The wallet processes the credential offer deeplink, resolves the issuer well-known configuration
                    in a tenant-aware context, and retrieves the issuer metadata as a plain JSON object (not a signed JWT).
                    
                    This test covers the happy path for unsigned issuer metadata retrieval in a multi-tenant configuration.
                    """
    )
    @Tag(ReportingTags.UCI_M1)
    @Tag(ReportingTags.UCI_M1A)
    @Tag(ReportingTags.HAPPY_PATH)
    void shouldSuccessfullyValidateUnsignedMetadataWithTenantId() {
        wallet.setSignedMetadataPreferred(false);
        var walletEntry = wallet.createWalletBatchEntry();
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final String deeplink = response.getOfferDeeplink();

        walletEntry.receiveDeepLinkAndValidateIt(URI.create(deeplink));
        walletEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(walletEntry));
        walletEntry.setToken(wallet.collectToken(walletEntry));

        final IssuerMetadata metadata = wallet.getIssuerWellKnownMetadata(walletEntry);

        assertThat(metadata).isNotNull();

        final JsonNode metadataRaw = walletEntry.getIssuerMetadataRaw();

        if (metadataRaw.has("iss")) {
            assertThat(metadataRaw.get("iss").asText())
                    .isEqualTo(issuerConfig.getIssuerDid());
        }

        assertThat(metadataRaw.get("sub")).isNull();

        assertThat(metadataRaw.has("iat"))
                .isFalse();

        if (metadataRaw.has("exp")) {
            assertThat(metadataRaw.get("exp").asLong())
                    .isGreaterThan(metadataRaw.get("iat").asLong());
        }
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-453",
            summary = "Reject a signed metadata request if the tenant id does not exist",
            description = """
                    This test validates that the issuer rejects a wallet's request for signed metadata when using
                    a non-existent tenant ID, returning HTTP 404 to prevent unauthorized metadata access.
                    """
    )
    @Tag(ReportingTags.UCI_M1)
    @Tag(ReportingTags.UCI_M1A)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            issuer = {ImageTags.STABLE},
            reason = "This feature is not available yet"
    )
    void verifierHasSignedMetadata_walletGetSignedMetadataOfNotFoundTenantId_thenRejected() {
        final WalletBatchEntry walletEntry = wallet.createWalletBatchEntry();
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final String deeplink = response.getOfferDeeplink();

        var offerDeeplink = new SwiyuDeeplink(deeplink);

        Assertions.assertTrue(offerDeeplink.hasTenantId());

        walletEntry.receiveDeepLinkAndValidateIt(URI.create(deeplink));

        walletEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(walletEntry));
        walletEntry.setToken(wallet.collectToken(walletEntry));

        final UUID randomID = UUID.randomUUID();
        final Pattern pattern = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
        final Matcher matcher = pattern.matcher(walletEntry.getIssuerUri().toString());
        final URI modifiedUri = URI.create(matcher.replaceAll(randomID.toString()));

        final WalletEntry modifiedWalletEntry = Mockito.spy(walletEntry);
        Mockito.doReturn(modifiedUri)
                .when(modifiedWalletEntry)
                .getIssuerUri();

        assertThrows(HttpServerErrorException.InternalServerError.class, () ->
                wallet.getIssuerWellKnownMetadata(modifiedWalletEntry)
        );
    }

    private ResponseEntity<String> performMetadataRequest(URI uri, String acceptHeader) {
        return RestClient.create()
                .get()
                .uri(uri)
                .header(HttpHeaders.ACCEPT, acceptHeader)
                .retrieve()
                .toEntity(String.class);
    }

    private static Stream<org.junit.jupiter.params.provider.Arguments> signedMetadataAcceptHeaderCases() {
        return Stream.of(
                org.junit.jupiter.params.provider.Arguments.of(
                        "Application/JWT;q=0.9,APPLICATION/JSON;q=0.1",
                        MediaType.parseMediaType("application/jwt"),
                        true
                ),
                org.junit.jupiter.params.provider.Arguments.of(
                        "application/jwt;q=0, application/json;q=1",
                        MediaType.APPLICATION_JSON,
                        false
                )
        );
    }

    private URI createTenantSpecificWellKnownUri(String suffix) {
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final SwiyuDeeplink deeplink = new SwiyuDeeplink(response.getOfferDeeplink());
        final URI issuerUri = wallet.getIssuerContext().getContextualizedUri(URI.create(deeplink.getCredentialIssuer()));
        return UriComponentsBuilder.fromUri(issuerUri)
                .path(suffix)
                .build()
                .toUri();
    }

    private JsonNode walletEntryJson(String body) throws Exception {
        return OBJECT_MAPPER.readTree(body);
    }
}
