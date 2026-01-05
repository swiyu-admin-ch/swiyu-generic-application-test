package ch.admin.bj.swiyu.swiyu_test_wallet.support;

import ch.admin.bj.swiyu.gen.verifier.model.*;
import ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests;

import java.util.List;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.es256Format;
import static ch.admin.bj.swiyu.swiyu_test_wallet.verifier.VerificationRequests.es256FormatNoKeyBinding;

public final class TestPresentationDefinitions {

    private TestPresentationDefinitions() {

    }

    public static PresentationDefinition universityPresentation() {
        final Constraint universityConstraint = new Constraint()
                .addFieldsItem(new Field().addPathItem("$.type"))
                .addFieldsItem(new Field().addPathItem("$.name"))
                .addFieldsItem(new Field().addPathItem("$.average_grade"));

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

    public static DcqlQueryDto universityPresentationDCQL() {
        final DcqlCredentialMetaDto meta = new DcqlCredentialMetaDto()
                .vctValues(List.of("http://default-issuer-url.admin.ch/oid4vci/vct/my-vct-v01"))
                .typeValues(List.of(List.of("string"), List.of("string"), List.of("number")));
        final DcqlClaimDto claimType = new DcqlClaimDto()
                .path(List.of("type"))
                .id(null)
                .values(List.of("Bachelor of Science"));
        final DcqlClaimDto claimName = new DcqlClaimDto()
                .path(List.of("name"))
                .id(null)
                .values(null);
        final DcqlClaimDto claimAverageGrade = new DcqlClaimDto()
                .path(List.of("average_grade"))
                .id(null)
                .values(null);
        final DcqlCredentialDto credential = new DcqlCredentialDto()
                .id("VerifiableCredential")
                .format("vc+sd-jwt")
                .meta(meta)
                .claims(List.of(claimType, claimName, claimAverageGrade))
                .claimSets(null)
                .requireCryptographicHolderBinding(true);
        return new DcqlQueryDto().credentials(List.of(credential));
    }
}
