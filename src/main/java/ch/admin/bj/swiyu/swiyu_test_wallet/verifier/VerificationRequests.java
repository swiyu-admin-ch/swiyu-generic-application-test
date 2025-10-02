package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import ch.admin.bj.swiyu.gen.verifier.model.Constraint;
import ch.admin.bj.swiyu.gen.verifier.model.CreateVerificationManagement;
import ch.admin.bj.swiyu.gen.verifier.model.Field;
import ch.admin.bj.swiyu.gen.verifier.model.FormatAlgorithm;
import ch.admin.bj.swiyu.gen.verifier.model.InputDescriptor;
import ch.admin.bj.swiyu.gen.verifier.model.PresentationDefinition;
import lombok.experimental.UtilityClass;

import java.util.UUID;

@UtilityClass
public class VerificationRequests {

    public static CreateVerificationManagement createDefaultRequest(boolean withKeyBinding) {

        Constraint lastNameConstraint = new Constraint()
                .addFieldsItem(new Field()
                        .addPathItem("$.type"));

        InputDescriptor lastNameInputDescriptor = new InputDescriptor()
                .id(UUID.randomUUID().toString())
                .name("Test")
                .putFormatItem("vc+sd-jwt", withKeyBinding ? es256Format() : es256FormatNoKeyBinding())
                .constraints(lastNameConstraint);

        PresentationDefinition presentation = new PresentationDefinition()
                .id(UUID.randomUUID().toString())
                .name("string")
                .purpose("string")
                .format(null)
                .addInputDescriptorsItem(lastNameInputDescriptor);

        return new CreateVerificationManagement()
                .acceptedIssuerDids(null)
                .jwtSecuredAuthorizationRequest(false)
                .presentationDefinition(presentation);
    }

    private static FormatAlgorithm es256Format() {
        return new FormatAlgorithm()
                .addKbJwtAlgValuesItem("ES256")
                .addSdJwtAlgValuesItem("ES256");
    }

    private static FormatAlgorithm es256FormatNoKeyBinding() {
        return new FormatAlgorithm()
                .addKbJwtAlgValuesItem(null)
                .addSdJwtAlgValuesItem("ES256");
    }
}
