package ch.admin.bj.swiyu.swiyu_test_wallet.fixture;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CredentialClaimsBuilder {

    private final Map<String, Object> claims;

    private CredentialClaimsBuilder(Map<String, Object> base) {
        this.claims = new HashMap<>(base);
    }

    public static CredentialClaimsBuilder base() {
        return new CredentialClaimsBuilder(
                CredentialClaimsFixtures.createBaseProfile()
        );
    }

    public static CredentialClaimsBuilder from(Map<String, Object> base) {
        return new CredentialClaimsBuilder(base);
    }

    public CredentialClaimsBuilder with(String key, Object value) {
        claims.put(key, value);
        return this;
    }

    public CredentialClaimsBuilder withNull(String key) {
        claims.put(key, null);
        return this;
    }

    public CredentialClaimsBuilder without(String key) {
        claims.remove(key);
        return this;
    }

    public CredentialClaimsBuilder withEmptyArray(String key) {
        claims.put(key, List.of());
        return this;
    }

    @SuppressWarnings("unchecked")
    public CredentialClaimsBuilder addToArray(String key, Object value) {
        List<Object> list = new java.util.ArrayList<>(
                (List<Object>) claims.getOrDefault(key, new java.util.ArrayList<>())
        );
        list.add(value);
        claims.put(key, list);
        return this;
    }

    public CredentialClaimsBuilder withArray(String key, List<?> values) {
        claims.put(key, values);
        return this;
    }

    public Map<String, Object> build() {
        return claims;
    }
}