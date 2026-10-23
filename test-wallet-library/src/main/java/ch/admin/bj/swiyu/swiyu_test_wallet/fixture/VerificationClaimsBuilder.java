package ch.admin.bj.swiyu.swiyu_test_wallet.fixture;

import ch.admin.bj.swiyu.gen.verifier.model.DcqlClaimDto;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class VerificationClaimsBuilder {

    private final List<DcqlClaimDto> requestedClaims = new ArrayList<>();

    public static VerificationClaimsBuilder claims() {
        return new VerificationClaimsBuilder();
    }

    public VerificationClaimsBuilder claim(String key, List<Object> values) {
        requestedClaims.add(new DcqlClaimDto()
                .path(Arrays.asList(key))
                .id(null)
                .values(values));
        return this;
    }

    public VerificationClaimsBuilder claim(String key) {
        return claim(key, null);
    }

    public VerificationClaimsBuilder arrayAll(String key) {
        requestedClaims.add(new DcqlClaimDto()
                .path(Arrays.asList(key, null))
                .id(null)
                .values(null));
        return this;
    }

    public VerificationClaimsBuilder arrayAllWithValues(String key, List<Object> values) {
        requestedClaims.add(new DcqlClaimDto()
                .path(Arrays.asList(key, null))
                .id(null)
                .values(values));
        return this;
    }

    public VerificationClaimsBuilder arrayIndex(String key, int index) {
        requestedClaims.add(new DcqlClaimDto()
                .path(Arrays.asList(key, index))
                .id(null)
                .values(null));
        return this;
    }

    public VerificationClaimsBuilder arrayIndex(String key, int index, List<Object> values) {
        requestedClaims.add(new DcqlClaimDto()
                .path(Arrays.asList(key, index))
                .id(null)
                .values(values));
        return this;
    }

    public VerificationClaimsBuilder arrayField(String key, String field, List<Object> values) {
        requestedClaims.add(new DcqlClaimDto()
                .path(Arrays.asList(key, null, field))
                .id(null)
                .values(values));
        return this;
    }

    public VerificationClaimsBuilder arrayField(String key, String field) {
        return arrayField(key, field, null);
    }

    public VerificationClaimsBuilder nested(String... path) {
        requestedClaims.add(new DcqlClaimDto()
                .path(Arrays.asList(path))
                .id(null)
                .values(null));
        return this;
    }

    public VerificationClaimsBuilder nestedWithValues(List<Object> values, String... path) {
        requestedClaims.add(new DcqlClaimDto()
                .path(Arrays.asList(path))
                .id(null)
                .values(values));
        return this;
    }

    public VerificationClaimsBuilder dcqlClaimDto(final DcqlClaimDto dcqlClaimDto) {
        requestedClaims.add(dcqlClaimDto);
        return this;
    }

    public List<DcqlClaimDto> build() {
        return requestedClaims;
    }
}