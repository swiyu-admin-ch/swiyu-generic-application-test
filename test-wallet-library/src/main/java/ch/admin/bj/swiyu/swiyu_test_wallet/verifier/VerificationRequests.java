package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import ch.admin.bj.swiyu.gen.verifier.model.Constraint;
import ch.admin.bj.swiyu.gen.verifier.model.CreateVerificationManagement;
import ch.admin.bj.swiyu.gen.verifier.model.Field;
import ch.admin.bj.swiyu.gen.verifier.model.FormatAlgorithm;
import ch.admin.bj.swiyu.gen.verifier.model.InputDescriptor;
import ch.admin.bj.swiyu.gen.verifier.model.PresentationDefinition;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.experimental.UtilityClass;

import java.util.UUID;

@UtilityClass
public class VerificationRequests {

    public static final String DEFAULT_ALG = "ES256";

    public static CreateVerificationManagement createDefaultRequest(boolean withKeyBinding) {

        Constraint lastNameConstraint = new Constraint()
                .addFieldsItem(new Field()
                        .addPathItem("$.name"));

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
                .trustAnchors(null)
                .jwtSecuredAuthorizationRequest(false)
                .responseMode(CreateVerificationManagement.ResponseModeEnum.POST)
                .presentationDefinition(presentation);
    }

    public static FormatAlgorithm es256Format() {
        return new FormatAlgorithm()
                .addKbJwtAlgValuesItem(DEFAULT_ALG)
                .addSdJwtAlgValuesItem(DEFAULT_ALG);
    }

    public static FormatAlgorithm es256FormatNoKeyBinding() {
        return new FormatAlgorithm()
                .addKbJwtAlgValuesItem(null)
                .addSdJwtAlgValuesItem(DEFAULT_ALG);
    }

    public String createDefaultRequestString(boolean withKeyBinding) {
        try {
            return new ObjectMapper().writeValueAsString(createDefaultRequest(withKeyBinding));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
