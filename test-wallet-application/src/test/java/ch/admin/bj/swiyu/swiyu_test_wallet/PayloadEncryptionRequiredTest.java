package ch.admin.bj.swiyu.swiyu_test_wallet;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.issuer.model.UpdateCredentialStatusRequestType;
import ch.admin.bj.swiyu.gen.verifier.model.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.SwiyuApiVersionConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.SdJwtDebugMetadata;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletEntry;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.AssertionsForClassTypes;
import org.assertj.core.data.MapEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestClientResponseException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@ActiveProfiles("issuer-encryption")
class PayloadEncryptionRequiredTest extends BaseTest {

    @BeforeEach
    void beforeEach() {
        wallet.setEncryptionPreferred(true);
    }


    @ParameterizedTest
    @EnumSource(SwiyuApiVersionConfig.class)
    @XrayTest(
            key = "EIDOMNI-628",
            summary = "Deferred credential request rejected when encryption is required but wallet sends unencrypted",
            description = """
                    This test validates that a wallet cannot retrieve a deferred credential using an unencrypted request
                    when the strict issuer profile requires encryption.
                    """
    )
    @Tag("uci_i1")
    @Tag("edge_case")
    void deferredCredentialRequestUnencrypted_strictIssuerRequired_thenRejected(final SwiyuApiVersionConfig apiVersion) {
        log.info("Creating deferred credential offer from strict issuer requiring encryption - API version: {}", apiVersion.name());
        final CredentialWithDeeplinkResponse response = issuerManager.createDeferredCredentialOffer("university_example_sd_jwt");

        log.info("Wallet collecting transaction ID from deferred offer");
        final WalletEntry entry = wallet.collectTransactionIdFromDeferredOffer(apiVersion, toUri(response.getOfferDeeplink()));
        AssertionsForClassTypes.assertThat(entry.getCredentialOffer()).isNotNull();

        final Map<String, Object> credentialStatus = Map.ofEntries(
                MapEntry.entry("average_grade", 4.00),
                MapEntry.entry("name", "Data Science"),
                MapEntry.entry("type", "Bachelor of Science")
        );

        log.info("Issuer updating credential status for deferred issuance");
        issuerManager.updateCredentialForDeferredFlowRequestCreation(response.getManagementId(), credentialStatus);
        issuerManager.updateState(response.getManagementId(), UpdateCredentialStatusRequestType.READY);

        log.info("Mocking wallet to force unencrypted request despite strict issuer requirement");
        final WalletEntry spiedEntry = Mockito.spy(entry);
        Mockito.doReturn(false).when(spiedEntry).isEncryptionEnabled();

        wallet.setEncryptionPreferred(false);

        log.info("Attempting to retrieve deferred credential with unencrypted request");
        final RestClientResponseException ex = assertThrows(RestClientResponseException.class, () ->
                wallet.getCredentialFromTransactionId(apiVersion, spiedEntry)
        );
    }

    @ParameterizedTest
    @EnumSource(SwiyuApiVersionConfig.class)
    @XrayTest(
            key = "EIDOMNI-629",
            summary = "Deferred credential with encryption key mismatch between credential request and deferred call",
            description = """
                    This test validates that deferred credentials are correctly encrypted with the ephemeral key
                    used at the time of the deferred credential request, even if different from the initial credential request key.
                    """
    )
    @Tag("uci_i1")
    @Tag("edge_case")
    void deferredCredentialEncryptionKeyMismatch_thenRetrieveWithCurrentKey(final SwiyuApiVersionConfig apiVersion) {
        final CredentialWithDeeplinkResponse response = issuerManager.createDeferredCredentialOffer("university_example_sd_jwt");

        log.info("Wallet collecting transaction ID from deferred offer");
        final WalletEntry entry = wallet.collectTransactionIdFromDeferredOffer(apiVersion, toUri(response.getOfferDeeplink()));
        AssertionsForClassTypes.assertThat(entry.getCredentialOffer()).isNotNull();

        final Map<String, Object> credentialStatus = Map.ofEntries(
                MapEntry.entry("average_grade", 3.50),
                MapEntry.entry("name", "Data Science"),
                MapEntry.entry("type", "Bachelor of Science")
        );

        log.info("Issuer updating credential status for deferred issuance with initial encryption key");
        issuerManager.updateCredentialForDeferredFlowRequestCreation(response.getManagementId(), credentialStatus);
        issuerManager.updateState(response.getManagementId(), UpdateCredentialStatusRequestType.READY);

        var result = wallet.getCredentialFromTransactionId(apiVersion, entry);

        final List<String> credentials = new ArrayList<>();
        if (apiVersion == SwiyuApiVersionConfig.V1) {
            result.getAsJsonArray("credentials").forEach(c ->
                    credentials.add(c.getAsJsonObject().get("credential").getAsString())
            );
        } else {
            credentials.add(result.get("credential").getAsString());
        }

        for (final String credential : credentials) {
            final SdJwtDebugMetadata sdjwt = new SdJwtDebugMetadata(credential);

            assertThat(sdjwt.isClaimValid(MapEntry.entry("average_grade", 3.5))).isTrue();
            assertThat(sdjwt.isClaimValid(MapEntry.entry("name", "Data Science"))).isTrue();
            assertThat(sdjwt.isClaimValid(MapEntry.entry("type", "Bachelor of Science"))).isTrue();
        }

        final ECKey originalKey = entry.getEphemeralEncryptionKey();
        entry.generateEphemeralEncryptionKey();
        final ECKey newKey = entry.getEphemeralEncryptionKey();

        assertThat(newKey).as("New ephemeral key should be different from original key").isNotEqualTo(originalKey);

        log.info("Wallet retrieving deferred credential with modified encryption key");
        final RestClientResponseException ex = assertThrows(RestClientResponseException.class, () ->
                wallet.getCredentialFromTransactionId(apiVersion, entry)
        );
    }
}
