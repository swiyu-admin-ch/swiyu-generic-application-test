package ch.admin.bj.swiyu.swiyu_test_wallet.support;

import ch.admin.bj.swiyu.gen.verifier.model.DcqlClaimDto;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlQueryDto;

import java.util.List;

import static ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures.IMAGE_MANDATORY_CLAIM_KEY;
import static ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures.NUMBER_MANDATORY_CLAIM_KEY;
import static ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures.TEXT_MANDATORY_CLAIM_KEY;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.dcqlClaim;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.defaultDcqlQuery;

public final class TestPresentationDefinitions {

    private TestPresentationDefinitions() {

    }

    public static DcqlQueryDto universityPresentationDCQL(final boolean holderBinding) {
        final List<DcqlClaimDto> claims = List.of(
                dcqlClaim(TEXT_MANDATORY_CLAIM_KEY),
                dcqlClaim(NUMBER_MANDATORY_CLAIM_KEY),
                dcqlClaim(IMAGE_MANDATORY_CLAIM_KEY)
        );

        return defaultDcqlQuery(claims, holderBinding);
    }

    public static DcqlQueryDto universityPresentationDCQL() {
        return universityPresentationDCQL(true);
    }
}
