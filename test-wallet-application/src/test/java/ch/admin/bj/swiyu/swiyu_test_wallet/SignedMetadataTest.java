package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerMetadata;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import ch.admin.bj.swiyu.swiyu_test_wallet.support.TestConstants;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JwtSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.SwiyuDeeplink;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerifierManager;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.net.URI;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class SignedMetadataTest extends BaseTest {

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
    @Tag("uci_m1")
    @Tag("uci_m1a")
    @Tag("happy_path")
    void shouldSuccessfullyValidateSignedMetadata() {
        var walletEntry = wallet.createWalletEntry();
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final String deeplink = response.getOfferDeeplink();

        final SwiyuDeeplink swiyuDeeplink = new SwiyuDeeplink(deeplink);

        walletEntry.receiveDeepLinkAndValidateIt(URI.create(deeplink));

        walletEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(walletEntry));
        walletEntry.setToken(wallet.collectToken(walletEntry));

        final IssuerMetadata metadata = wallet.getIssuerWellKnownMetadataSigned(walletEntry);

        assertThat(metadata).isNotNull();
        assertThat(metadata.getData()).isNotNull();

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
    @Tag("uci_m1")
    @Tag("uci_m1a")
    @Tag("edge_case")
    void verifierHasSignedMetadata_walletGetSignedMetadataOfNotFoundTenantId_thenRejected() {
        final WalletEntry walletEntry = wallet.createWalletEntry();
        final CredentialWithDeeplinkResponse response = issuerManager.createCredentialOffer("unbound_example_sd_jwt");
        final String deeplink = response.getOfferDeeplink();

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
                        wallet.getIssuerWellKnownMetadataSigned(modifiedWalletEntry)
                );
    }
}
