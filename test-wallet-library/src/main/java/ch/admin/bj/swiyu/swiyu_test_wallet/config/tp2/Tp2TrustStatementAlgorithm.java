package ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2;

/**
 * Signature algorithms exposed by the TP2 Trust Registry test double.
 *
 * <p>{@link #EDDSA_LEGACY} is deliberately available only to exercise the issuer's
 * algorithm allowlist. It is not an allowed Trust Statement algorithm for
 * EIDOMNI-1050.</p>
 */
public enum Tp2TrustStatementAlgorithm {
    ES256,
    ED25519,
    EDDSA_LEGACY
}
