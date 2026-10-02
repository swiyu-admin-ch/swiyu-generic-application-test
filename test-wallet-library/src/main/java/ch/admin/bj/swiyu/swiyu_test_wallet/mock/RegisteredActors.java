package ch.admin.bj.swiyu.swiyu_test_wallet.mock;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockAttestationAuthority;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.TrustConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** The Credential Issuers, Verifiers, trust anchor and key attestation authority the mock services know about. */
final class RegisteredActors {

    private final Map<String, IssuerConfig> issuersByDid = new ConcurrentHashMap<>();
    private final Map<String, VerifierConfig> verifiersByDid = new ConcurrentHashMap<>();
    private TrustConfig trustConfig;
    private MockAttestationAuthority attestationAuthority;

    void addIssuer(final IssuerConfig issuer) {
        issuersByDid.put(issuer.getIssuerDid(), issuer);
    }

    void addVerifier(final VerifierConfig verifier) {
        verifiersByDid.put(verifier.getVerifierDid(), verifier);
    }

    Optional<IssuerConfig> issuer(final String did) {
        return Optional.ofNullable(issuersByDid.get(did));
    }

    Collection<IssuerConfig> issuers() {
        return issuersByDid.values();
    }

    /** The issuer whose Business Entity id (SWIYU partner id) is {@code partnerId}, as the Credential Issuer sends it to the registry. */
    Optional<IssuerConfig> issuerByPartnerId(final String partnerId) {
        return issuersByDid.values().stream()
                .filter(issuer -> partnerId != null && partnerId.equals(issuer.getSwiyuPartnerId()))
                .findFirst();
    }

    TrustConfig trustConfig() {
        return trustConfig;
    }

    void trustConfig(final TrustConfig trustConfig) {
        this.trustConfig = trustConfig;
    }

    void attestationAuthority(final MockAttestationAuthority attestationAuthority) {
        this.attestationAuthority = attestationAuthority;
    }
}
