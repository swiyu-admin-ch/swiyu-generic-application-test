package ch.admin.bj.swiyu.swiyu_test_wallet.fixture;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class CredentialConfigurationFixtures {

    public static final int BATCH_SIZE = 10;

    public static final String BOUND_EXAMPLE_SD_JWT =
            "bound_example_sd_jwt";

    public static final String BOUND_DISCLOSURE_EXAMPLE_SD_JWT =
            "bound_disclosure_example_sd_jwt";

    public static final String BOUND_IDENTITY_PROFILE_SD_JWT =
            "bound_identity_profile_sd_jwt";

    public static final String UNBOUND_EXAMPLE_SD_JWT =
            "unbound_example_sd_jwt";

    public static final String UNIVERSITY_EXAMPLE_HIGH_KEY_ATTESTATION_REQUIRED_SD_JWT =
            "university_example_high_key_attestation_required_sd_jwt";

    public static final String UNIVERSITY_EXAMPLE_ANY_KEY_ATTESTATION_REQUIRED_SD_JWT =
            "university_example_any_key_attestation_required_sd_jwt";

    public static final String NESTED_EXAMPLE = "bound_nested_example_sd_jwt";
}