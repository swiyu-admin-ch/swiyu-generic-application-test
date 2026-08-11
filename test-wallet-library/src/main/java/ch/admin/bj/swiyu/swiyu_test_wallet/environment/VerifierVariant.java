package ch.admin.bj.swiyu.swiyu_test_wallet.environment;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;

public enum VerifierVariant {
    DEFAULT("default", false),
    CACHED("cached", false),
    HSM("hsm", true),
    MANAGEMENT_KEYCLOAK("management_keycloak", false),
    SHORT_LIVED_REQUEST_OBJECT("short_lived_request_object", false);

    private static final long CACHED_TRUST_REGISTRY_MAX_CACHE_SIZE = 1_000;
    private static final long CACHED_TRUST_REGISTRY_MAX_CACHE_TTL_SECONDS = 3;
    private static final long CACHED_JWK_CACHE_TTL_MILLIS = 2_000;
    private static final long CACHED_TRUST_STATEMENT_CACHE_TTL_MILLIS = 3_000;

    private final String surname;
    private final boolean hsm;

    VerifierVariant(final String surname, final boolean hsm) {
        this.surname = surname;
        this.hsm = hsm;
    }

    public boolean requiresHsm() {
        return hsm;
    }

    public boolean requiresKeycloak() {
        return this == MANAGEMENT_KEYCLOAK;
    }

    public VerifierImageConfig imageConfig(final VerifierImageConfig template) {
        final VerifierImageConfig config = copy(template);
        config.setSurname(surname);
        config.setEnableHsm(hsm);
        if (this == CACHED) {
            config.setTrustRegistryMaxCacheSize(CACHED_TRUST_REGISTRY_MAX_CACHE_SIZE);
            config.setTrustRegistryMaxCacheTtlSeconds(CACHED_TRUST_REGISTRY_MAX_CACHE_TTL_SECONDS);
            config.setJwkCacheTtlMillis(CACHED_JWK_CACHE_TTL_MILLIS);
            config.setTrustStatementCacheTtlMillis(CACHED_TRUST_STATEMENT_CACHE_TTL_MILLIS);
        }
        if (this == SHORT_LIVED_REQUEST_OBJECT) {
            config.setRequestObjectTtlSeconds(SHORT_LIVED_REQUEST_OBJECT_TTL_SECONDS);
        }
        return config;
    }

    private static VerifierImageConfig copy(final VerifierImageConfig source) {
        final VerifierImageConfig target = new VerifierImageConfig();
        target.setBaseImage(source.getBaseImage());
        target.setImageTag(source.getImageTag());
        target.setSwiyuPartnerId(source.getSwiyuPartnerId());
        target.setSurname(source.getSurname());
        target.setEnableHsm(source.isEnableHsm());
        target.setTrustRegistryMaxCacheSize(source.getTrustRegistryMaxCacheSize());
        target.setTrustRegistryMaxCacheTtlSeconds(source.getTrustRegistryMaxCacheTtlSeconds());
        target.setJwkCacheTtlMillis(source.getJwkCacheTtlMillis());
        target.setTrustStatementCacheTtlMillis(source.getTrustStatementCacheTtlMillis());
        target.setRequestObjectTtlSeconds(source.getRequestObjectTtlSeconds());
        target.setHsmUser(source.getHsmUser());
        target.setHsmPassword(source.getHsmPassword());
        target.setHsmUserPin(source.getHsmUserPin());
        target.setHsmKeyId(source.getHsmKeyId());
        target.setHsmKeyPin(source.getHsmKeyPin());
        return target;
    }
}
