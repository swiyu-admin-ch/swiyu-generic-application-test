package ch.admin.bj.swiyu.swiyu_test_wallet.fixture;

import ch.admin.bj.swiyu.gen.verifier.model.DcqlClaimDto;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class VerificationClaimsBuilder {

    private final List<DcqlClaimDto> claims = new ArrayList<>();

    public static VerificationClaimsBuilder claims() {
        return new VerificationClaimsBuilder();
    }

    public VerificationClaimsBuilder claim(String key, List<Object> values) {
        claims.add(new DcqlClaimDto()
                .path(Arrays.asList(key))
                .id(null)
                .values(values));
        return this;
    }

    public VerificationClaimsBuilder claim(String key) {
        return claim(key, null);
    }

    public VerificationClaimsBuilder arrayAll(String key) {
        claims.add(new DcqlClaimDto()
                .path(Arrays.asList(key, null))
                .id(null)
                .values(null));
        return this;
    }

    public VerificationClaimsBuilder arrayAllWithValues(String key, List<Object> values) {
        claims.add(new DcqlClaimDto()
                .path(Arrays.asList(key, null))
                .id(null)
                .values(values));
        return this;
    }

    public VerificationClaimsBuilder arrayIndex(String key, int index) {
        claims.add(new DcqlClaimDto()
                .path(Arrays.asList(key, index))
                .id(null)
                .values(null));
        return this;
    }

    public VerificationClaimsBuilder arrayIndex(String key, int index, List<Object> values) {
        claims.add(new DcqlClaimDto()
                .path(Arrays.asList(key, index))
                .id(null)
                .values(values));
        return this;
    }

    public VerificationClaimsBuilder arrayField(String key, String field, List<Object> values) {
        claims.add(new DcqlClaimDto()
                .path(Arrays.asList(key, null, field))
                .id(null)
                .values(values));
        return this;
    }

    public VerificationClaimsBuilder arrayField(String key, String field) {
        return arrayField(key, field, null);
    }

    public VerificationClaimsBuilder nested(String... path) {
        claims.add(new DcqlClaimDto()
                .path(Arrays.asList(path))
                .id(null)
                .values(null));
        return this;
    }

    public VerificationClaimsBuilder nestedWithValues(List<Object> values, String... path) {
        claims.add(new DcqlClaimDto()
                .path(Arrays.asList(path))
                .id(null)
                .values(values));
        return this;
    }

    public List<DcqlClaimDto> build() {
        return claims;
    }
}