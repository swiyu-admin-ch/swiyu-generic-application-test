package ch.admin.bj.swiyu.swiyu_test_wallet.fixture;

import ch.admin.bj.swiyu.gen.verifier.model.DcqlClaimDto;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.Arrays;
import java.util.List;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class VerificationClaimsFixtures {

    // 🔹 Base (minimal)

    public static List<DcqlClaimDto> base() {
        return VerificationClaimsBuilder.claims()
                .claim(CredentialClaimsConstants.KEY_NAME)
                .build();
    }

    public static List<DcqlClaimDto> mandatory() {
        return VerificationClaimsBuilder.claims()
                .claim(CredentialClaimsConstants.KEY_NAME)
                .claim(CredentialClaimsConstants.KEY_ADDRESS)
                .arrayAll(CredentialClaimsConstants.KEY_NATIONALITIES)
                .claim("birth_year")
                .build();
    }

    public static List<DcqlClaimDto> all() {
        return VerificationClaimsBuilder.claims()
                .claim("name")
                .claim("address")
                .arrayAll("degrees")
                .arrayAll("nationalities")
                .claim("birth_year")
                .arrayAll("favorite_numbers")
                .claim("portrait")
                .claim("additional_info")
                .arrayAll("additional_info_list")
                .build();
    }

    public static List<DcqlClaimDto> degreeTypes() {
        return VerificationClaimsBuilder.claims()
                .arrayField("degrees", "type")
                .build();
    }

    public static List<DcqlClaimDto> bachelorOnly() {
        return VerificationClaimsBuilder.claims()
                .arrayField("degrees", "type", List.of("Bachelor of Science"))
                .build();
    }

    public static List<DcqlClaimDto> nonMatchingValue() {
        return VerificationClaimsBuilder.claims()
                .arrayField("degrees", "type", List.of("NonExisting"))
                .build();
    }
}