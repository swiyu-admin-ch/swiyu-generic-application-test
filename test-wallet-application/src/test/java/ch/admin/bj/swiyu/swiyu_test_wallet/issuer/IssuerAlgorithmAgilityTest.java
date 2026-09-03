package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialStatusType;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.UseIssuers;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt.SdJwtBatchAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.JwtProof;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.util.List;
import java.util.Map;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
@UseIssuers(IssuerVariant.CRYPTO_AGILITY)
@DisableIfImageTag(
        issuer = {ImageTags.STABLE},
        reason = "EIDOMNI-1050 Ed25519 Proof JWT validation is not available in the stable issuer image."
)
class IssuerAlgorithmAgilityTest extends BaseTest {

    private static final List<String> SUPPORTED_PROOF_ALGORITHMS = List.of("ES256", "Ed25519");

    @Test
    @XrayTest(
            key = "EIDOMNI-1315",
            summary = "Issuer accepts an Ed25519-signed OID4VCI Proof JWT",
            description = """
                    Given issuer metadata advertises ES256 and Ed25519 for JWT holder-binding proofs.
                    And a wallet creates an Ed25519 Proof JWT bound to the issuer audience and a fresh c_nonce.
                    When the wallet submits the credential request through the complete OID4VCI flow.
                    Then the Generic Issuer validates the proof, issues the credential, and binds it to the Ed25519 key.
                    """
    )
    @Tag(ReportingTags.UCI_C1)
    @Tag(ReportingTags.UCI_I1)
    @Tag(ReportingTags.HAPPY_PATH)
    void boundCredential_whenProofJwtUsesEd25519_thenIssuanceSucceeds() throws Exception {
        // Given
        final String credentialConfigurationId = CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT;
        final Map<String, Object> subjectClaims = CredentialSubjectFixtures.completeEmployeeProfile();
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                credentialConfigurationId,
                subjectClaims
        );
        final WalletBatchEntry walletEntry = wallet.createWalletBatchEntry();
        walletEntry.receiveDeepLinkAndValidateIt(toUri(offer.getOfferDeeplink()));
        walletEntry.setIssuerWellKnownConfiguration(wallet.getIssuerWellKnownConfiguration(walletEntry));
        walletEntry.setIssuerMetadata(wallet.getIssuerWellKnownMetadata(walletEntry));
        walletEntry.setCredentialConfigurationSupported();

        assertThat(walletEntry.getIssuerMetadata()
                .getCredentialConfigurationsSupported()
                .get(credentialConfigurationId)
                .getProofTypesSupported()
                .get("jwt")
                .getProofSigningAlgValuesSupported())
                .as("Algorithms advertised for OID4VCI JWT proofs")
                .containsExactlyElementsOf(SUPPORTED_PROOF_ALGORITHMS);

        walletEntry.setToken(wallet.collectToken(walletEntry));
        final String cNonce = wallet.collectCNonce(walletEntry);
        walletEntry.setCNonce(cNonce);
        final OctetKeyPair holderKey = new OctetKeyPairGenerator(Curve.Ed25519)
                .algorithm(JWSAlgorithm.Ed25519)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("holder-ed25519-key")
                .generate();
        walletEntry.setProofsFromJwt(List.of(JwtProof.ed25519(
                walletEntry.getIssuerMetadata().getCredentialIssuer(),
                cNonce,
                holderKey
        )));

        final SignedJWT proofJwt = SignedJWT.parse(walletEntry.getProofsAsJwt().getFirst());
        assertThat(proofJwt.getHeader().getAlgorithm())
                .as("OID4VCI Proof JWT algorithm")
                .isEqualTo(JWSAlgorithm.Ed25519);
        assertThat(proofJwt.getHeader().getType())
                .as("OID4VCI Proof JWT type")
                .isEqualTo(new JOSEObjectType("openid4vci-proof+jwt"));
        assertThat(proofJwt.getHeader().getJWK())
                .as("Public holder key embedded in the Proof JWT")
                .isEqualTo(holderKey.toPublicJWK());
        assertThat(proofJwt.getJWTClaimsSet().getAudience())
                .as("OID4VCI Proof JWT audience")
                .containsExactly(walletEntry.getIssuerMetadata().getCredentialIssuer());
        assertThat(proofJwt.getJWTClaimsSet().getStringClaim("nonce"))
                .as("OID4VCI Proof JWT c_nonce")
                .isEqualTo(cNonce);

        // When
        wallet.getVerifiableCredentialFromIssuer(walletEntry);

        // Then
        SdJwtBatchAssert.assertThat(walletEntry.getIssuedCredentials())
                .hasBatchSize(1)
                .areUnique()
                .allHaveExactlyInAnyOrderDisclosures(subjectClaims);
        issuerManager.verifyStatus(offer.getManagementId(), CredentialStatusType.ISSUED);

        final SignedJWT issuedCredential = SignedJWT.parse(
                walletEntry.getIssuedCredentials().getFirst().split("~", 2)[0]
        );
        final Map<String, Object> confirmationClaim = issuedCredential
                .getJWTClaimsSet()
                .getJSONObjectClaim("cnf");
        assertThat(confirmationClaim)
                .as("Issued credential confirmation claim")
                .containsKey("jwk");

        @SuppressWarnings("unchecked")
        final JWK credentialHolderKey = JWK.parse((Map<String, Object>) confirmationClaim.get("jwk"));
        assertThat(credentialHolderKey.toPublicJWK())
                .as("Credential is bound to the Ed25519 key proven by the wallet")
                .isEqualTo(holderKey.toPublicJWK());
    }
}
