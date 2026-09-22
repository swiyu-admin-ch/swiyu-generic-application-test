package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import app.getxray.xray.junit.customjunitxml.annotations.XrayTest;
import ch.admin.bj.swiyu.gen.issuer.model.CredentialWithDeeplinkResponse;
import ch.admin.bj.swiyu.gen.verifier.model.ManagementResponse;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.gen.verifier.model.TrustAnchor;
import ch.admin.bj.swiyu.gen.verifier.model.VerificationStatus;
import ch.admin.bj.swiyu.swiyu_test_wallet.BaseTest;
import ch.admin.bj.swiyu.swiyu_test_wallet.CompleteEnvironmentTestConfiguration;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ImageTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.junit.DisableIfImageTag;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error.ApiErrorAssert;
import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.WalletBatchEntry;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.net.URI;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig.UNTRUSTED_REGISTRY_HOST;
import static ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result.VerificationFailureAssert.assertIssuerUntrusted;
import static ch.admin.bj.swiyu.swiyu_test_wallet.test_support.verification_result.VerificationFailureAssert.assertRejected;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockserver.model.HttpRequest.request;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(CompleteEnvironmentTestConfiguration.class)
class VerifierIssuerKeyResolutionTest extends BaseTest {

    @ParameterizedTest(name = "[{index}] trusted issuer configured through {0}")
    @EnumSource(TrustedIssuerConfiguration.class)
    @XrayTest(
            key = "EIDOMNI-1195",
            summary = "Verifier rejects credentials whose trusted iss conflicts with an untrusted kid",
            description = """
                    Given an attacker-controlled issuer DID that is resolvable but not trusted.
                    And a valid SD-JWT signed by the attacker's key whose kid identifies the attacker DID,
                    while its iss claim impersonates a trusted issuer.
                    And the credential has no status reference, so revocation cannot mask the issuer/key trust decision.
                    When the wallet presents the credential using either an accepted issuer allow-list or a direct trust anchor.
                    Then the verifier resolves the kid, rejects the untrusted signing DID, and ends the verification as FAILED.
                    """)
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1B)
    @Tag(ReportingTags.EDGE_CASE)
    void verification_whenTrustedIssuerClaimConflictsWithUntrustedKid_thenRejected(
            final TrustedIssuerConfiguration trustedIssuerConfiguration
    ) throws ParseException, JOSEException {
        // Given
        final WalletBatchEntry batchEntry = issueBoundCredential();
        final AttackerIssuer attacker = createResolvableUntrustedIssuer();
        final String trustedIssuerDid = issuerConfig.getIssuerDid();
        final String maliciousCredential = resignWithAttackerKey(
                batchEntry.getVerifiableCredential(0),
                trustedIssuerDid,
                attacker.config()
        );
        replaceIssuedCredential(batchEntry, maliciousCredential);

        final SignedJWT maliciousIssuerJwt = issuerJwt(maliciousCredential);
        assertThat(maliciousIssuerJwt.getJWTClaimsSet().getIssuer())
                .as("The attacker-controlled iss claim impersonates the trusted issuer")
                .isEqualTo(trustedIssuerDid);
        assertThat(maliciousIssuerJwt.getHeader().getKeyID())
                .as("The kid remains bound to the untrusted attacker's DID")
                .isEqualTo(attacker.config().getIssuerAssertKeyId())
                .doesNotStartWith(trustedIssuerDid + "#");
        assertThat(maliciousIssuerJwt.getJWTClaimsSet().getClaims())
                .as("Status validation must not mask the issuer/kid trust decision")
                .doesNotContainKey("status");
        assertThat(maliciousIssuerJwt.verify(new ECDSAVerifier(
                (ECPublicKey) attacker.config().getKeyPair().getPublic()
        )))
                .as("The malicious credential must have a valid signature from the DID identified by kid")
                .isTrue();

        final ManagementResponse verification = createVerification(
                trustedIssuerConfiguration,
                trustedIssuerDid
        );
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
        final RequestObject requestObject = wallet.getVerificationRequestObject(
                verification.getVerificationDeeplink()
        );
        final String presentation = batchEntry.createPresentationForSdJwtIndex(0, requestObject);
        final int attackerDidRequestsBefore = didDocumentRequests(attacker.didDocumentPath());

        // When
        assertRejected(
                () -> wallet.respondToVerification(requestObject, presentation),
                verifierManager,
                verification.getId(),
                ex -> ApiErrorAssert.assertThat(ex)
                        .hasStatus(400)
                        .hasError("invalid_transaction_data")
                        .hasDetail("issuer_not_accepted")
                        .hasErrorCode("issuer_not_accepted")
                        .hasErrorDescription("Issuer not in list of accepted issuers or connected to trust anchor"),
                evaluation -> assertIssuerUntrusted(evaluation)
        );

        // Then
        assertThat(didDocumentRequests(attacker.didDocumentPath()))
                .as("The verifier must resolve the DID selected from the credential kid")
                .isGreaterThan(attackerDidRequestsBefore);
    }

    @ParameterizedTest(name = "[{index}] credential with {0} iss claim")
    @EnumSource(CredentialIssuerClaim.class)
    @XrayTest(
            key = "EIDOMNI-1362",
            summary = "Generic Verifier ignores a missing or mismatched iss claim in SD-JWT credentials",
            description = """
                    Given a valid SD-JWT credential signed by the trusted DID identified by its kid header,
                    while the iss claim is either absent or different from that DID.
                    When the wallet presents the credential to the Generic Verifier.
                    Then the Verifier derives issuer trust from kid and completes the verification successfully.
                    """)
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1B)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC},
            reason = "EIDOMNI-1362 requires centralized JWT validation in the Generic Verifier"
    )
    void verification_whenIssuerClaimIsIgnoredAndKidIsTrusted_thenSuccess(
            final CredentialIssuerClaim issuerClaim
    ) throws ParseException, JOSEException {
        // Given
        final WalletBatchEntry batchEntry = issueBoundCredential();
        final String credential = resignCredential(
                batchEntry.getVerifiableCredential(0),
                issuerClaim.value(),
                issuerConfig
        );
        replaceIssuedCredential(batchEntry, credential);

        final SignedJWT issuerJwt = issuerJwt(credential);
        assertThat(issuerJwt.getJWTClaimsSet().getIssuer())
                .as("The test credential must contain the selected iss variant")
                .isEqualTo(issuerClaim.value());
        assertThat(issuerJwt.getHeader().getKeyID())
                .as("The trusted signer must remain identified by kid")
                .isEqualTo(issuerConfig.getIssuerAssertKeyId());
        assertThat(issuerJwt.verify(new ECDSAVerifier(
                (ECPublicKey) issuerConfig.getKeyPair().getPublic()
        )))
                .as("The credential signature must remain valid after changing iss")
                .isTrue();

        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(issuerConfig.getIssuerDid())
                .withDCQL()
                .createManagementResponse();
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
        final RequestObject requestObject = wallet.getVerificationRequestObject(
                verification.getVerificationDeeplink()
        );
        final String presentation = batchEntry.createPresentationForSdJwtIndex(0, requestObject);
        final int callbacksBefore = awaitStableVerifierCallbacks();

        // When
        wallet.respondToVerification(requestObject, presentation);

        // Then
        verifierManager.verifyState(verification.getId(), VerificationStatus.SUCCESS);
        awaitOneVerifierCallback(callbacksBefore);
    }

    @Test
    @XrayTest(
            key = "EIDOMNI-1363",
            summary = "Generic Verifier rejects credential DIDs outside the swiyu Base Registry",
            description = """
                    Given a correctly signed SD-JWT credential whose kid resolves to a reachable host outside the
                    configured Base Registry allowlist.
                    When the wallet presents the credential to the Generic Verifier.
                    Then the Verifier fails the verification before making any request to that host.
                    """)
    @Tag(ReportingTags.UCV_O1)
    @Tag(ReportingTags.UCV_O1B)
    @Tag(ReportingTags.EDGE_CASE)
    @DisableIfImageTag(
            verifier = {ImageTags.STABLE, ImageTags.RC},
            reason = "EIDOMNI-1363 requires centralized JWT validation in the Generic Verifier"
    )
    void verification_whenCredentialDidIsOutsideBaseRegistry_thenRejectedWithoutResolution()
            throws ParseException, JOSEException {
        // Given
        final WalletBatchEntry batchEntry = issueBoundCredential();
        final AttackerIssuer externalIssuer = createIssuerAtRegistryHost(UNTRUSTED_REGISTRY_HOST);
        final String credential = resignCredential(
                batchEntry.getVerifiableCredential(0),
                externalIssuer.config().getIssuerDid(),
                externalIssuer.config()
        );
        replaceIssuedCredential(batchEntry, credential);

        final SignedJWT issuerJwt = issuerJwt(credential);
        assertThat(issuerJwt.getHeader().getKeyID())
                .as("The credential kid must identify the external registry DID")
                .isEqualTo(externalIssuer.config().getIssuerAssertKeyId());
        assertThat(issuerJwt.verify(new ECDSAVerifier(
                (ECPublicKey) externalIssuer.config().getKeyPair().getPublic()
        )))
                .as("The external credential signature must be cryptographically valid")
                .isTrue();

        final ManagementResponse verification = verifierManager.verificationRequest()
                .acceptedIssuerDid(externalIssuer.config().getIssuerDid())
                .withDCQL()
                .createManagementResponse();
        verifierManager.verifyState(verification.getId(), VerificationStatus.PENDING);
        final RequestObject requestObject = wallet.getVerificationRequestObject(
                verification.getVerificationDeeplink()
        );
        final String presentation = batchEntry.createPresentationForSdJwtIndex(0, requestObject);
        final int didRequestsBefore = didDocumentRequests(externalIssuer.didDocumentPath());
        final int callbacksBefore = awaitStableVerifierCallbacks();

        // When
        assertRejected(
                () -> wallet.respondToVerification(requestObject, presentation),
                verifierManager,
                verification.getId(),
                exception -> ApiErrorAssert.assertThat(exception)
                        .hasStatus(400)
                        .hasError("invalid_transaction_data"),
                evaluation -> assertThat(evaluation)
                        .as("The credential must have a failed evaluation")
                        .isNotNull()
        );

        // Then
        assertThat(didDocumentRequests(externalIssuer.didDocumentPath()))
                .as("The Verifier must reject the DID before attempting resolution")
                .isEqualTo(didRequestsBefore);
        awaitOneVerifierCallback(callbacksBefore);
    }

    private WalletBatchEntry issueBoundCredential() {
        final CredentialWithDeeplinkResponse offer = issuerManager.createCredentialOffer(
                CredentialConfigurationFixtures.BOUND_EXAMPLE_SD_JWT
        );
        return wallet.collectOffer(toUri(offer.getOfferDeeplink()));
    }

    private AttackerIssuer createResolvableUntrustedIssuer() {
        return createIssuerAtRegistryHost(MockServerClientConfig.MOCKSERVER_HOST);
    }

    private AttackerIssuer createIssuerAtRegistryHost(final String registryHost) {
        final URI registryEntry = URI.create(
                "https://%s/api/v1/did/%s".formatted(
                        registryHost,
                        UUID.randomUUID()
                )
        );
        final IssuerConfig attackerConfig = IssuerConfig.createIssuerConfig(registryEntry, false, null);
        mockServerClientConfig.replaceDidLog(attackerConfig.getIssuerDid(), attackerConfig.getIssuerDidLog());
        return new AttackerIssuer(attackerConfig, registryEntry.getPath() + "/did.jsonl");
    }

    private String resignWithAttackerKey(
            final String originalCredential,
            final String trustedIssuerDid,
            final IssuerConfig attackerConfig
    ) throws ParseException, JOSEException {
        return resignCredential(originalCredential, trustedIssuerDid, attackerConfig);
    }

    private String resignCredential(
            final String originalCredential,
            final String issuerClaim,
            final IssuerConfig signingIssuer
    ) throws ParseException, JOSEException {
        final int disclosureSeparator = originalCredential.indexOf('~');
        assertThat(disclosureSeparator)
                .as("The issued SD-JWT must contain disclosures")
                .isPositive();

        final SignedJWT originalIssuerJwt = SignedJWT.parse(
                originalCredential.substring(0, disclosureSeparator)
        );
        final JWSHeader signerHeader = new JWSHeader.Builder(originalIssuerJwt.getHeader().getAlgorithm())
                .type(originalIssuerJwt.getHeader().getType())
                .keyID(signingIssuer.getIssuerAssertKeyId())
                .build();
        final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder(originalIssuerJwt.getJWTClaimsSet())
                .claim("status", null);
        if (issuerClaim == null) {
            claims.claim("iss", null);
        } else {
            claims.issuer(issuerClaim);
        }
        final SignedJWT resignedIssuerJwt = new SignedJWT(signerHeader, claims.build());
        resignedIssuerJwt.sign(ECCryptoSupport.createECDSASigner(signingIssuer.getKeyPair().getPrivate()));

        return resignedIssuerJwt.serialize() + originalCredential.substring(disclosureSeparator);
    }

    private void replaceIssuedCredential(
            final WalletBatchEntry batchEntry,
            final String maliciousCredential
    ) {
        batchEntry.clearIssuedCredentials();
        batchEntry.addIssuedCredential(maliciousCredential);
    }

    private SignedJWT issuerJwt(final String credential) throws ParseException {
        return SignedJWT.parse(credential.substring(0, credential.indexOf('~')));
    }

    private ManagementResponse createVerification(
            final TrustedIssuerConfiguration trustedIssuerConfiguration,
            final String trustedIssuerDid
    ) {
        final VerifierManager.VerificationRequestBuilder requestBuilder = verifierManager.verificationRequest()
                .withDCQL();

        switch (trustedIssuerConfiguration) {
            case ACCEPTED_ISSUER_ALLOW_LIST -> requestBuilder.acceptedIssuerDid(trustedIssuerDid);
            case DIRECT_TRUST_ANCHOR -> requestBuilder.trustAnchor(
                    new TrustAnchor()
                            .did(trustedIssuerDid)
                            .trustRegistryUri("https://%s/untrusted".formatted(
                                    MockServerClientConfig.MOCKSERVER_HOST
                            ))
            );
        }

        return requestBuilder.createManagementResponse();
    }

    private int didDocumentRequests(final String didDocumentPath) {
        return mockServerClient.retrieveRecordedRequests(
                request()
                        .withMethod("GET")
                        .withPath(didDocumentPath)
        ).length;
    }

    private enum TrustedIssuerConfiguration {
        ACCEPTED_ISSUER_ALLOW_LIST,
        DIRECT_TRUST_ANCHOR
    }

    private enum CredentialIssuerClaim {
        MISSING(null),
        MISMATCHED("did:example:untrusted-credential-issuer");

        private final String value;

        CredentialIssuerClaim(final String value) {
            this.value = value;
        }

        String value() {
            return value;
        }
    }

    private record AttackerIssuer(IssuerConfig config, String didDocumentPath) {
    }
}
