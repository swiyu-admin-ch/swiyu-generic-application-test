package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialManagementDto;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockAttestationAuthority;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerHandle;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.CredentialOffer;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_status.CredentialStatusAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.issuance_deeplink.IssuanceDeeplinkAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.Wallet;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.RestClient;

import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import({CompleteEnvironmentTestConfiguration.class, RegressionEnvironmentTestConfiguration.class})
@Tag(ReportingTags.VERSION_REGRESSION)
class HistoricalOfferVersionRegressionTest {

    @Autowired
    private RegressionEnvironmentFactory regressionEnvironment;

    @Autowired
    private MockAttestationAuthority mockAttestationAuthority;

    @Test
    @XrayTest(
            key = "EIDOMNI-1282",
            summary = "Offer created by Previous Issuer can be issued by Candidate Issuer",
            description = """
                    Creates an unconsumed credential offer on the Previous Issuer, starts the Candidate Issuer on the
                    same database schema, and verifies that the latest fake wallet can complete the original offer.
                    """)
    void offerCreatedByPrevious_whenIssuedByCandidate_thenSuccess() {
        try (final IssuerVersionTransition transition = regressionEnvironment.issuerTransition()) {
            // Given an unconsumed offer created by Previous Issuer
            final IssuerHandle previousIssuer = transition.startPrevious();
            final String expectedIssuerDid = previousIssuer.config().getIssuerDid();
            final String expectedDatabaseSchema = previousIssuer.imageConfig().getDbSchema();
            final Map<String, Object> expectedDisclosures = CredentialOffer.defaultSubjectData();
            final CredentialWithDeeplinkResponse previousOffer =
                    transition.preparePrevious(this::createNonDeferredOffer);

            assertThat(previousOffer)
                    .as("Offer created by Previous Issuer")
                    .isNotNull();
            final UUID historicalOfferId = previousOffer.getManagementId();
            final String historicalOfferDeeplink = previousOffer.getOfferDeeplink();

            assertThat(historicalOfferId)
                    .as("Previous offer management ID")
                    .isNotNull();
            assertThat(historicalOfferDeeplink)
                    .as("Previous offer deeplink")
                    .isNotBlank();
            IssuanceDeeplinkAssert.assertThat(historicalOfferDeeplink)
                    .isWellFormed()
                    .containsCredentialConfigurationId(
                            CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
                    );
            CredentialStatusAssert.assertThat(previousIssuer.manager().getStatusById(historicalOfferId))
                    .hasStatus(CredentialStatusType.OFFERED);

            // When Candidate Issuer starts on the same database schema
            final IssuerHandle candidateIssuer = transition.upgradeToCandidate();
            final CredentialManagementDto currentOffer =
                    candidateIssuer.manager().getCredentialById(historicalOfferId);

            // Then Candidate Issuer preserves the identity and historical offer
            assertThat(candidateIssuer.config().getIssuerDid())
                    .as("Candidate Issuer DID")
                    .isEqualTo(expectedIssuerDid);
            assertThat(candidateIssuer.imageConfig().getDbSchema())
                    .as("Candidate Issuer database schema")
                    .isEqualTo(expectedDatabaseSchema);
            assertThat(currentOffer)
                    .as("Historical offer loaded by Candidate Issuer")
                    .isNotNull();
            assertThat(currentOffer.getId())
                    .as("Historical offer management ID")
                    .isEqualTo(historicalOfferId);
            CredentialStatusAssert.assertThat(candidateIssuer.manager().getStatusById(historicalOfferId))
                    .hasStatus(CredentialStatusType.OFFERED);

            // When the latest fake wallet collects the historical offer
            final Wallet currentWallet = latestWalletFor(candidateIssuer);
            final WalletBatchEntry currentBatch = currentWallet.collectOffer(toUri(historicalOfferDeeplink));

            // Then Candidate Issuer returns the expected credentials and marks the offer as issued
            SdJwtBatchAssert.assertThat(currentBatch.getIssuedCredentials())
                    .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                    .areUnique()
                    .allHaveExactlyInAnyOrderDisclosures(expectedDisclosures);
            currentBatch.getIssuedCredentials().forEach(currentCredential ->
                    SdJwtAssert.assertThat(currentCredential)
                            .hasPayloadClaim("iss", expectedIssuerDid)
            );
            CredentialStatusAssert.assertThat(candidateIssuer.manager().getStatusById(historicalOfferId))
                    .hasStatus(CredentialStatusType.ISSUED);
        }
    }

    private CredentialWithDeeplinkResponse createNonDeferredOffer(final IssuerHandle previousIssuer) {
        if (!previousIssuer.imageConfig().isEnableJwtAuth()) {
            return previousIssuer.manager().createCredentialOffer(
                    CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
            );
        }
        assertThat(previousIssuer.jwtKey())
                .as("Previous Issuer management JWT key")
                .isNotNull();
        return previousIssuer.manager().createCredentialWithSignedJwt(
                previousIssuer.jwtKey(),
                previousIssuer.keyId(),
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
        );
    }

    private Wallet latestWalletFor(final IssuerHandle candidateIssuer) {
        final Wallet wallet = new Wallet(RestClient.builder().build(), candidateIssuer.serviceLocation(), null);
        wallet.setUseDPoP(candidateIssuer.imageConfig().isEnforceDpop());
        wallet.setUseEncryption(candidateIssuer.imageConfig().isEncryptionEnforce());
        wallet.setSignedMetadataPreferred(candidateIssuer.imageConfig().isSignedMetadata());
        wallet.setMockAttestationAuthority(mockAttestationAuthority);
        return wallet;
    }
}
