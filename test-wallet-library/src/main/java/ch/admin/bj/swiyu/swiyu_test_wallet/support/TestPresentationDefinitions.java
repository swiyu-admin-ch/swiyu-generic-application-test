package ch.admin.bj.swiyu.swiyu_test_wallet.support;

import ch.admin.bj.swiyu.gen.verifier.model.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialConfigurationFixtures;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests;

import java.util.List;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.fixture.CredentialSubjectFixtures.*;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.es256Format;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.es256FormatNoKeyBinding;

public final class TestPresentationDefinitions {

    private TestPresentationDefinitions() {

    }

    public static PresentationDefinition universityPresentation() {
        final Constraint universityConstraint = new Constraint()
                .addFieldsItem(new Field().addPathItem("$.name"));

        final InputDescriptor universityInputDescriptor = new InputDescriptor()
                .id(UUID.randomUUID().toString())
                .name("University Credential")
                .putFormatItem("vc+sd-jwt", es256Format())
                .constraints(universityConstraint);

        return new PresentationDefinition()
                .id(UUID.randomUUID().toString())
                .name("University Presentation")
                .purpose("Present university degree information")
                .format(null)
                .addInputDescriptorsItem(universityInputDescriptor);
    }

    public static DcqlQueryDto universityPresentationDCQL(final boolean holderBinding) {
        final DcqlCredentialMetaDto meta = new DcqlCredentialMetaDto()
                .vctValues(List.of("http://default-issuer-url.admin.ch/oid4vci/vct/my-vct-v01"))
                .typeValues(null);

        final DcqlCredentialDto credential = new DcqlCredentialDto()
                .id("VerifiableCredential")
                .format("vc+sd-jwt")
                .meta(meta)
                .claims(List.of(
                        new DcqlClaimDto()
                                .id(null)
                                .path(List.of(TEXT_MANDATORY_CLAIM_KEY))
                                .values(null),
                        new DcqlClaimDto()
                                .id(null)
                                .path(List.of(NUMBER_MANDATORY_CLAIM_KEY))
                                .values(null),
                        new DcqlClaimDto()
                                .id(null)
                                .path(List.of(IMAGE_MANDATORY_CLAIM_KEY))
                                .values(null)
                ))
                .claimSets(null)
                .requireCryptographicHolderBinding(holderBinding);
        return new DcqlQueryDto().credentials(List.of(credential));
    }

    public static DcqlQueryDto universityPresentationDCQL() {
        return universityPresentationDCQL(true);
    }
}
