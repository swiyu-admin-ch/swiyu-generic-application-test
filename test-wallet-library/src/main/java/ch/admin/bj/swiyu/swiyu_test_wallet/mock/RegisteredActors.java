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

    /** Any registered issuer: the one the mock falls back on when it cannot tell which issuer a request is for. */
    IssuerConfig anyIssuer() {
        return issuersByDid.values().stream()
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No issuer config registered in MockServices"));
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
