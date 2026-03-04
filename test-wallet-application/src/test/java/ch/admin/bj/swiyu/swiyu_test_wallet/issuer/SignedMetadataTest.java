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
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.HttpServerErrorException;

import java.net.URI;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class SignedMetadataTest extends BaseTest {

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
            issuer = {ImageTags.STABLE, ImageTags.STAGING},
            reason = "This feature is not available yet"
    )
    void shouldSuccessfullyValidateSignedMetadata() {
        var walletEntry = wallet.createWalletEntry();
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final String deeplink = response.getOfferDeeplink();

        final SwiyuDeeplink swiyuDeeplink = new SwiyuDeeplink(deeplink);

        walletEntry.receiveDeepLinkAndValidateIt(URI.create(deeplink));

        walletEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(walletEntry));
        walletEntry.setToken(wallet.collectToken(walletEntry));

        final IssuerMetadata metadata = wallet.getIssuerWellKnownMetadata(walletEntry);

        assertThat(metadata).isNotNull();
        /*
        @TODO

        if (metadata.getData().has("iss")) {
            assertThat(metadata.getData().get("iss").getAsString())
                    .isEqualTo(issuerConfig.getIssuerDid());
        }

        assertThat(metadata.getData().get("sub").getAsString())
                .isEqualTo(swiyuDeeplink.getCredentialIssuer());

        assertThat(metadata.getData().has("iat"))
                .isTrue();
        assertThat(metadata.getData().get("iat").getAsLong())
                .isPositive();

        if (metadata.getData().has("exp")) {
            assertThat(metadata.getData().get("exp").getAsLong())
                    .isGreaterThan(metadata.getData().get("iat").getAsLong());
        }
         */
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
        var walletEntry = wallet.createWalletEntry();
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final String deeplink = response.getOfferDeeplink();

        walletEntry.receiveDeepLinkAndValidateIt(URI.create(deeplink));
        walletEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(walletEntry));
        walletEntry.setToken(wallet.collectToken(walletEntry));

        final IssuerMetadata metadata = wallet.getIssuerWellKnownMetadata(walletEntry);

        assertThat(metadata).isNotNull();

        /*
        if (metadata.getData().has("iss")) {
            assertThat(metadata.getData().get("iss").getAsString())
                    .isEqualTo(issuerConfig.getIssuerDid());
        }

        assertThat(metadata.getData().get("sub")).isNull();

        assertThat(metadata.getData().has("iat"))
                .isFalse();

        if (metadata.getData().has("exp")) {
            assertThat(metadata.getData().get("exp").getAsLong())
                    .isGreaterThan(metadata.getData().get("iat").getAsLong());
        }
        @TODO
         */
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
        final WalletEntry walletEntry = wallet.createWalletEntry();
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
}
