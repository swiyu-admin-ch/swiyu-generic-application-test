package ch.admin.bj.swiyu.swiyu_test_wallet.flows;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CreateCredentialOfferRequest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialOfferMetadataDto;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.StatusListCreate;
import ch.admin.bj.swiyu.gen.issuer.model.StatusListCreateConfig;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JwtSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.UseWallet;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.zip.InflaterInputStream;

import static ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result.CredentialEvaluationAssert.assertEvaluation;
import static ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result.TokenStatusListValues.REVOKED;
import static ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result.TokenStatusListValues.SUSPENDED;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.DEFAULT_CREDENTIAL_ID;
import static org.assertj.core.api.Assertions.assertThat;

@UseIssuers(IssuerVariant.COMPLETE)
@UseWallet(dpop = true, encryption = true, signedMetadata = true)
class ConcurrentCredentialStatusE2ETest extends BaseTest {

    @Test
    @XrayTest(key = "EIDOMNI-1567",
            summary = "Credential Issuer preserves concurrent suspension and revocation in one shared status list",
            description = """
                    Given two issued Credentials from different management entries sharing a fresh status list.
                    When the Business Issuer suspends one and revokes the other concurrently.
                    Then both management states and the published list preserve their respective changes,
                    the stored list matches the registry, and the Verifier rejects both Credentials with the corresponding status.
                    Spec: Token Status List draft 20 §4.2 Status List in JSON Format and §8.3 Validation Rules;
                    Swiss VC profile Token Status List §7.1. Publication consistency is a project business invariant.
                    """)
    @Tag(ReportingTags.EDGE_CASE)
    @Tag(ReportingTags.UCI_C3_UPDATE_THE_STATUS_OF_AN_OFFER_OR_VC)
    @Tag(ReportingTags.UCV_O2C_CHECK_VC_STATUS_IN_REGISTRY)
    void credentialStatus_whenSuspensionAndRevocationRaceOnSharedList_thenBothChangesReachVerifier() throws Exception {
        // Given
        final var list = issuerManager.getStatusListApi().createStatusList(new StatusListCreate()
                .maxLength(100000).config(new StatusListCreateConfig().bits(2)));
        final var offerA = issuerManager.createCredential(offerOnList(list.getStatusRegistryUrl()));
        final var offerB = issuerManager.createCredential(offerOnList(list.getStatusRegistryUrl()));
        final var walletB = newWallet();
        final var entryA = wallet.collectOffer(toUri(offerA.getOfferDeeplink()), 1);
        final var entryB = walletB.collectOffer(toUri(offerB.getOfferDeeplink()), 1);
        final var referenceA = JwtSupport.decodePayloadToJsonNode(entryA.getVerifiableCredential(0).split("~", 2)[0])
                .path("status").path("status_list");
        final var referenceB = JwtSupport.decodePayloadToJsonNode(entryB.getVerifiableCredential(0).split("~", 2)[0])
                .path("status").path("status_list");
        assertThat(referenceA.path("uri").asString())
                .isEqualTo(list.getStatusRegistryUrl());
        assertThat(referenceB.path("uri").asString())
                .isEqualTo(list.getStatusRegistryUrl());
        assertThat(referenceA.path("idx").asInt())
                .isNotEqualTo(referenceB.path("idx").asInt());
        final int callbacksBefore = awaitStableIssuerCallbacks();
        final CyclicBarrier start = new CyclicBarrier(2);

        // When
        try (var executor = Executors.newFixedThreadPool(2)) {
            final var suspension = executor.submit(() -> {
                start.await(5, TimeUnit.SECONDS);
                issuerManager.updateState(offerA.getManagementId(), UpdateCredentialStatusRequestType.SUSPENDED);
                return null;
            });
            final var revocation = executor.submit(() -> {
                start.await(5, TimeUnit.SECONDS);
                issuerManager.updateState(offerB.getManagementId(), UpdateCredentialStatusRequestType.REVOKED);
                return null;
            });
            suspension.get(20, TimeUnit.SECONDS);
            revocation.get(20, TimeUnit.SECONDS);
        }

        // Then
        issuerManager.verifyStatus(offerA.getManagementId(), CredentialStatusType.SUSPENDED);
        issuerManager.verifyStatus(offerB.getManagementId(), CredentialStatusType.REVOKED);
        final String published = restClient.get()
                .uri("http://%s:%d%s".formatted(mockServerContainer.getHost(), mockServerContainer.getServerPort(),
                        URI.create(list.getStatusRegistryUrl()).getPath()))
                .retrieve().body(String.class);
        final var statusList = JwtSupport.decodePayloadToJsonNode(published).path("status_list");
        final String compressed = statusList.path("lst").asString();
        final byte[] statuses;
        try (var decompressor = new InflaterInputStream(new ByteArrayInputStream(Base64.getUrlDecoder().decode(compressed)))) {
            statuses = decompressor.readAllBytes();
        }
        final int bits = statusList.path("bits").asInt();
        assertThat(bits)
                .isEqualTo(2);
        assertThat(statusAt(statuses, bits, referenceA.path("idx").asInt()))
                .isEqualTo(SUSPENDED);
        assertThat(statusAt(statuses, bits, referenceB.path("idx").asInt()))
                .isEqualTo(REVOKED);
        try (var query = connection.prepareStatement("SELECT status_zipped FROM %s.status_list WHERE uri = ?"
                .formatted(issuerImageConfig.getDbSchema()))) {
            query.setString(1, list.getStatusRegistryUrl());
            try (var result = query.executeQuery()) {
                assertThat(result.next())
                        .isTrue();
                assertThat(result.getString(1))
                        .as("The published list must contain exactly the persisted status data")
                        .isEqualTo(compressed);
            }
        }
        awaitNIssuerCallback(callbacksBefore, 2);
        assertThat(awaitStableIssuerCallbacks())
                .isEqualTo(callbacksBefore + 2);

        final var verificationA = verifierManager.verificationRequest().acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withDCQL().encrypted().createManagementResponse();
        final var requestA = wallet.getVerificationRequestObject(verificationA.getVerificationDeeplink());
        wallet.respondToVerification(requestA, entryA.createPresentationForSdJwtIndex(0, requestA));
        final var rejectedA = verifierManager.verifyState(verificationA.getId(), VerificationStatus.FAILED);
        assertEvaluation(rejectedA, DEFAULT_CREDENTIAL_ID, false, SUSPENDED);

        final var verificationB = verifierManager.verificationRequest().acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withDCQL().encrypted().createManagementResponse();
        final var requestB = walletB.getVerificationRequestObject(verificationB.getVerificationDeeplink());
        walletB.respondToVerification(requestB, entryB.createPresentationForSdJwtIndex(0, requestB));
        final var rejectedB = verifierManager.verifyState(verificationB.getId(), VerificationStatus.FAILED);
        assertEvaluation(rejectedB, DEFAULT_CREDENTIAL_ID, false, REVOKED);
    }

    private CreateCredentialOfferRequest offerOnList(final String uri) {
        return new CreateCredentialOfferRequest()
                .metadataCredentialSupportedId(List.of(CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT))
                .credentialSubjectData(CredentialSubjectFixtures.completeEmployeeProfile())
                .credentialMetadata(new CredentialOfferMetadataDto().deferred(false))
                .offerValiditySeconds(600).statusLists(List.of(uri));
    }

    /** Token Status List draft 20 §4.1 stores each entry starting with the least significant bits of its byte. */
    private int statusAt(final byte[] statuses, final int bits, final int index) {
        final int offset = index * bits;
        return (statuses[offset / Byte.SIZE] >>> (offset % Byte.SIZE)) & ((1 << bits) - 1);
    }
}
