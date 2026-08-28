package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockAttestationAuthority;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerHandle;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.CredentialOffer;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
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
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import({CompleteEnvironmentTestConfiguration.class, RegressionEnvironmentTestConfiguration.class})
@Tag(ReportingTags.VERSION_REGRESSION)
class IssuerOfferVersionRegressionTest {

    private static final String CREDENTIAL_CONFIGURATION_ID =
            CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;
    private static final String ISSUER_CLAIM = "iss";

    @Autowired
    private RegressionEnvironmentFactory regressionEnvironment;

    @Autowired
    private MockAttestationAuthority mockAttestationAuthority;

    @Test
    @XrayTest(
            key = "EIDOMNI-1283",
            summary = "Issuer offer lifecycle remains compatible from Previous to Candidate",
            description = """
                    Prepares immediate, deferred, suspended and cancelled offer states on the Previous Issuer. Once all
                    historical artifacts are persisted, the test starts the Candidate Issuer only once on the same
                    schema and validates the complete offer lifecycle matrix with the latest fake wallet.
                    """)
    void offersPreparedByPrevious_whenIssuerUpgradesOnce_thenCandidateCompletesLifecycleMatrix() {
        try (final IssuerVersionTransition transition = regressionEnvironment.issuerTransition()) {
            final IssuerHandle previousIssuer = transition.startPrevious();
            final String expectedIssuerDid = previousIssuer.config().getIssuerDid();
            final String expectedDatabaseSchema = previousIssuer.imageConfig().getDbSchema();
            final Map<String, Object> expectedDisclosures = CredentialOffer.defaultSubjectData();

            // Given all historical offer states have been prepared by Previous Issuer
            final PreviousOfferScenarios scenarios = transition.preparePrevious(issuer ->
                    preparePreviousOfferScenarios(issuer, expectedIssuerDid, expectedDisclosures)
            );

            // When Candidate Issuer starts once, after every Previous offer has been prepared
            final IssuerHandle candidateIssuer = transition.upgradeToCandidate();
            assertThat(candidateIssuer.config().getIssuerDid())
                    .as("Candidate Issuer DID")
                    .isEqualTo(expectedIssuerDid);
            assertThat(candidateIssuer.imageConfig().getDbSchema())
                    .as("Candidate Issuer database schema")
                    .isEqualTo(expectedDatabaseSchema);

            // Then Candidate issues the non-deferred offer created by Previous
            CredentialStatusAssert.assertThat(candidateIssuer.manager().getStatusById(
                            scenarios.immediateOffer().getManagementId()
                    ))
                    .hasStatus(CredentialStatusType.OFFERED);
            final WalletBatchEntry immediateBatch = latestWalletFor(candidateIssuer)
                    .collectOffer(toUri(scenarios.immediateOffer().getOfferDeeplink()));
            SdJwtBatchAssert.assertThat(immediateBatch.getIssuedCredentials())
                    .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                    .areUnique()
                    .allHaveExactlyInAnyOrderDisclosures(expectedDisclosures);
            immediateBatch.getIssuedCredentials().forEach(credential ->
                    SdJwtAssert.assertThat(credential)
                            .hasPayloadClaim(ISSUER_CLAIM, expectedIssuerDid)
            );
            CredentialStatusAssert.assertThat(candidateIssuer.manager().getStatusById(
                            scenarios.immediateOffer().getManagementId()
                    ))
                    .hasStatus(CredentialStatusType.ISSUED);

            // And Candidate issues the deferred transaction made READY by Previous
            final DeferredScenario readyByPrevious = scenarios.readyByPrevious();
            CredentialStatusAssert.assertThat(candidateIssuer.manager().getStatusById(
                            readyByPrevious.managementId()
                    ))
                    .hasStatus(CredentialStatusType.READY);
            readyByPrevious.wallet().useIssuer(candidateIssuer)
                    .getCredentialFromTransactionId(readyByPrevious.walletBatch());
            SdJwtBatchAssert.assertThat(readyByPrevious.walletBatch().getIssuedCredentials())
                    .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                    .areUnique()
                    .allHaveExactlyInAnyOrderDisclosures(expectedDisclosures);
            readyByPrevious.walletBatch().getIssuedCredentials().forEach(credential ->
                    SdJwtAssert.assertThat(credential)
                            .hasPayloadClaim(ISSUER_CLAIM, expectedIssuerDid)
            );
            CredentialStatusAssert.assertThat(
                            candidateIssuer.manager().getStatusById(readyByPrevious.managementId())
                    )
                    .hasStatus(CredentialStatusType.ISSUED);

            // And Candidate makes the historical DEFERRED transaction READY and issues it
            final DeferredScenario readyByCandidate = scenarios.readyByCandidate();
            CredentialStatusAssert.assertThat(candidateIssuer.manager().getStatusById(
                            readyByCandidate.managementId()
                    ))
                    .hasStatus(CredentialStatusType.DEFERRED);
            updateStatus(
                    candidateIssuer,
                    readyByCandidate.managementId(),
                    UpdateCredentialStatusRequestType.READY
            );
            readyByCandidate.wallet().useIssuer(candidateIssuer)
                    .getCredentialFromTransactionId(readyByCandidate.walletBatch());
            SdJwtBatchAssert.assertThat(readyByCandidate.walletBatch().getIssuedCredentials())
                    .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                    .areUnique()
                    .allHaveExactlyInAnyOrderDisclosures(expectedDisclosures);
            readyByCandidate.walletBatch().getIssuedCredentials().forEach(credential ->
                    SdJwtAssert.assertThat(credential)
                            .hasPayloadClaim(ISSUER_CLAIM, expectedIssuerDid)
            );
            CredentialStatusAssert.assertThat(
                            candidateIssuer.manager().getStatusById(readyByCandidate.managementId())
                    )
                    .hasStatus(CredentialStatusType.ISSUED);

            // And Candidate revalidates the credential batch suspended by Previous
            CredentialStatusAssert.assertThat(candidateIssuer.manager().getStatusById(
                            scenarios.suspendedCredential().managementId()
                    ))
                    .hasStatus(CredentialStatusType.SUSPENDED);
            updateStatus(
                    candidateIssuer,
                    scenarios.suspendedCredential().managementId(),
                    UpdateCredentialStatusRequestType.ISSUED
            );
            CredentialStatusAssert.assertThat(candidateIssuer.manager().getStatusById(
                            scenarios.suspendedCredential().managementId()
                    ))
                    .hasStatus(CredentialStatusType.ISSUED);
            final WalletBatchEntry suspendedBatch = scenarios.suspendedCredential().walletBatch();
            SdJwtBatchAssert.assertThat(suspendedBatch.getIssuedCredentials())
                    .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                    .areUnique()
                    .allHaveExactlyInAnyOrderDisclosures(expectedDisclosures);
            suspendedBatch.getIssuedCredentials().forEach(credential ->
                    SdJwtAssert.assertThat(credential)
                            .hasPayloadClaim(ISSUER_CLAIM, expectedIssuerDid)
            );

            // And Candidate performs the complete deferred flow for an offer only created by Previous
            CredentialStatusAssert.assertThat(candidateIssuer.manager().getStatusById(
                            scenarios.unconsumedDeferredOffer().getManagementId()
                    ))
                    .hasStatus(CredentialStatusType.OFFERED);
            final Wallet candidateWallet = latestWalletFor(candidateIssuer);
            final WalletBatchEntry candidateDeferredBatch = candidateWallet.collectTransactionIdFromDeferredOffer(
                    toUri(scenarios.unconsumedDeferredOffer().getOfferDeeplink())
            );
            assertThat(candidateDeferredBatch.getTransactionId())
                    .as("Candidate deferred transaction ID")
                    .isNotNull();
            final UUID candidateDeferredId = scenarios.unconsumedDeferredOffer().getManagementId();
            CredentialStatusAssert.assertThat(candidateIssuer.manager().getStatusById(candidateDeferredId))
                    .hasStatus(CredentialStatusType.DEFERRED);
            updateStatus(candidateIssuer, candidateDeferredId, UpdateCredentialStatusRequestType.READY);
            candidateWallet.getCredentialFromTransactionId(candidateDeferredBatch);
            SdJwtBatchAssert.assertThat(candidateDeferredBatch.getIssuedCredentials())
                    .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                    .areUnique()
                    .allHaveExactlyInAnyOrderDisclosures(expectedDisclosures);
            candidateDeferredBatch.getIssuedCredentials().forEach(credential ->
                    SdJwtAssert.assertThat(credential)
                            .hasPayloadClaim(ISSUER_CLAIM, expectedIssuerDid)
            );
            CredentialStatusAssert.assertThat(candidateIssuer.manager().getStatusById(candidateDeferredId))
                    .hasStatus(CredentialStatusType.ISSUED);

            // And Candidate refuses the deferred transaction cancelled by Previous
            CredentialStatusAssert.assertThat(candidateIssuer.manager().getStatusById(
                            scenarios.cancelledDeferred().managementId()
                    ))
                    .hasStatus(CredentialStatusType.CANCELLED);
            final HttpClientErrorException exception = assertThrows(
                    HttpClientErrorException.class,
                    () -> scenarios.cancelledDeferred().wallet().useIssuer(candidateIssuer)
                            .getCredentialFromTransactionId(scenarios.cancelledDeferred().walletBatch())
            );
            ApiErrorAssert.assertThat(exception)
                    .hasStatus(400)
                    .hasError("credential_request_denied")
                    .hasErrorDescription(
                            "The credential cannot be issued anymore, the offer was either cancelled or expired"
                    );
            CredentialStatusAssert.assertThat(candidateIssuer.manager().getStatusById(
                            scenarios.cancelledDeferred().managementId()
                    ))
                    .hasStatus(CredentialStatusType.CANCELLED);
        }
    }

    private PreviousOfferScenarios preparePreviousOfferScenarios(
            final IssuerHandle previousIssuer,
            final String expectedIssuerDid,
            final Map<String, Object> expectedDisclosures) {
        final CredentialWithDeeplinkResponse immediateOffer = createOffer(previousIssuer, false);
        assertThat(immediateOffer)
                .as("Historical immediate offer")
                .isNotNull();
        assertThat(immediateOffer.getManagementId())
                .as("Historical immediate offer management ID")
                .isNotNull();
        assertThat(immediateOffer.getOfferDeeplink())
                .as("Historical immediate offer deeplink")
                .isNotBlank();
        IssuanceDeeplinkAssert.assertThat(immediateOffer.getOfferDeeplink())
                .isWellFormed()
                .containsCredentialConfigurationId(CREDENTIAL_CONFIGURATION_ID);
        CredentialStatusAssert.assertThat(
                        previousIssuer.manager().getStatusById(immediateOffer.getManagementId())
                )
                .hasStatus(CredentialStatusType.OFFERED);

        final DeferredScenario readyByPrevious = startDeferredTransaction(previousIssuer);
        updateStatus(
                previousIssuer,
                readyByPrevious.managementId(),
                UpdateCredentialStatusRequestType.READY
        );
        CredentialStatusAssert.assertThat(previousIssuer.manager().getStatusById(readyByPrevious.managementId()))
                .hasStatus(CredentialStatusType.READY);

        final DeferredScenario readyByCandidate = startDeferredTransaction(previousIssuer);

        final CredentialWithDeeplinkResponse suspendedOffer = createOffer(previousIssuer, false);
        final WalletBatchEntry suspendedBatch = latestWalletFor(previousIssuer)
                .collectOffer(toUri(suspendedOffer.getOfferDeeplink()));
        SdJwtBatchAssert.assertThat(suspendedBatch.getIssuedCredentials())
                .hasBatchSize(CredentialConfigurationFixtures.BATCH_SIZE)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(expectedDisclosures);
        suspendedBatch.getIssuedCredentials().forEach(credential ->
                SdJwtAssert.assertThat(credential)
                        .hasPayloadClaim(ISSUER_CLAIM, expectedIssuerDid)
        );
        updateStatus(
                previousIssuer,
                suspendedOffer.getManagementId(),
                UpdateCredentialStatusRequestType.SUSPENDED
        );
        CredentialStatusAssert.assertThat(previousIssuer.manager().getStatusById(suspendedOffer.getManagementId()))
                .hasStatus(CredentialStatusType.SUSPENDED);
        final IssuedScenario suspendedCredential =
                new IssuedScenario(suspendedOffer.getManagementId(), suspendedBatch);

        final CredentialWithDeeplinkResponse unconsumedDeferredOffer = createOffer(previousIssuer, true);
        assertThat(unconsumedDeferredOffer)
                .as("Historical deferred offer")
                .isNotNull();
        assertThat(unconsumedDeferredOffer.getManagementId())
                .as("Historical deferred offer management ID")
                .isNotNull();
        assertThat(unconsumedDeferredOffer.getOfferDeeplink())
                .as("Historical deferred offer deeplink")
                .isNotBlank();
        IssuanceDeeplinkAssert.assertThat(unconsumedDeferredOffer.getOfferDeeplink())
                .isWellFormed()
                .containsCredentialConfigurationId(CREDENTIAL_CONFIGURATION_ID);
        CredentialStatusAssert.assertThat(
                        previousIssuer.manager().getStatusById(unconsumedDeferredOffer.getManagementId())
                )
                .hasStatus(CredentialStatusType.OFFERED);

        final DeferredScenario cancelledDeferred = startDeferredTransaction(previousIssuer);
        updateStatus(
                previousIssuer,
                cancelledDeferred.managementId(),
                UpdateCredentialStatusRequestType.CANCELLED
        );
        CredentialStatusAssert.assertThat(previousIssuer.manager().getStatusById(cancelledDeferred.managementId()))
                .hasStatus(CredentialStatusType.CANCELLED);

        return new PreviousOfferScenarios(
                immediateOffer,
                readyByPrevious,
                readyByCandidate,
                suspendedCredential,
                unconsumedDeferredOffer,
                cancelledDeferred
        );
    }

    private DeferredScenario startDeferredTransaction(final IssuerHandle issuer) {
        final CredentialWithDeeplinkResponse offer = createOffer(issuer, true);
        final Wallet wallet = latestWalletFor(issuer);
        final WalletBatchEntry walletBatch =
                wallet.collectTransactionIdFromDeferredOffer(toUri(offer.getOfferDeeplink()));
        assertThat(walletBatch.getTransactionId())
                .as("Previous deferred transaction ID")
                .isNotNull();
        CredentialStatusAssert.assertThat(issuer.manager().getStatusById(offer.getManagementId()))
                .hasStatus(CredentialStatusType.DEFERRED);
        return new DeferredScenario(offer.getManagementId(), wallet, walletBatch);
    }

    private CredentialWithDeeplinkResponse createOffer(
            final IssuerHandle issuer,
            final boolean deferred) {
        if (!issuer.imageConfig().isEnableJwtAuth()) {
            return issuer.manager().createCredentialOffer(
                    CREDENTIAL_CONFIGURATION_ID,
                    CredentialOffer.defaultSubjectData(),
                    deferred
            );
        }
        assertThat(issuer.jwtKey())
                .as("Issuer management JWT key")
                .isNotNull();
        return issuer.manager().createCredentialWithSignedJwt(
                issuer.jwtKey(),
                issuer.keyId(),
                CREDENTIAL_CONFIGURATION_ID,
                deferred
        );
    }

    private void updateStatus(
            final IssuerHandle issuer,
            final UUID managementId,
            final UpdateCredentialStatusRequestType status) {
        if (!issuer.imageConfig().isEnableJwtAuth()) {
            issuer.manager().updateState(managementId, status);
            return;
        }
        assertThat(issuer.jwtKey())
                .as("Issuer management JWT key")
                .isNotNull();
        issuer.manager().updateStateWithSignedJwt(
                issuer.jwtKey(),
                issuer.keyId(),
                managementId,
                status
        );
    }

    private Wallet latestWalletFor(final IssuerHandle issuer) {
        final Wallet wallet = new Wallet(RestClient.builder().build(), issuer.serviceLocation(), null);
        wallet.setUseDPoP(issuer.imageConfig().isEnforceDpop());
        wallet.setUseEncryption(issuer.imageConfig().isEncryptionEnforce());
        wallet.setSignedMetadataPreferred(issuer.imageConfig().isSignedMetadata());
        wallet.setMockAttestationAuthority(mockAttestationAuthority);
        return wallet;
    }

    private record PreviousOfferScenarios(
            CredentialWithDeeplinkResponse immediateOffer,
            DeferredScenario readyByPrevious,
            DeferredScenario readyByCandidate,
            IssuedScenario suspendedCredential,
            CredentialWithDeeplinkResponse unconsumedDeferredOffer,
            DeferredScenario cancelledDeferred) {
    }

    private record DeferredScenario(UUID managementId, Wallet wallet, WalletBatchEntry walletBatch) {
    }

    private record IssuedScenario(UUID managementId, WalletBatchEntry walletBatch) {
    }
}
