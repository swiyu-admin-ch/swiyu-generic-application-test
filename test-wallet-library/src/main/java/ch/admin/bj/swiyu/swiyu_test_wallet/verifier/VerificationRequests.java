package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import ch.admin.bj.swiyu.gen.verifier.model.CreateVerificationManagement;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlClaimDto;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlCredentialDto;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlCredentialMetaDto;
import ch.admin.bj.swiyu.gen.verifier.model.DcqlQueryDto;
import ch.admin.bj.swiyu.gen.verifier.model.ResponseModeType;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.experimental.UtilityClass;

import java.util.List;

import static ch.admin.bj.swiyu.swiyu_test_wallet.support.TestConstants.ISSUER_URL;

@UtilityClass
public class VerificationRequests {

    public static final String DEFAULT_CREDENTIAL_ID = "VerifiableCredential";
    public static final String DEFAULT_FORMAT = "vc+sd-jwt";
    public static final String DEFAULT_VCT = ISSUER_URL + "/oid4vci/vct/my-vct-v01";

    public static CreateVerificationManagement createDefaultRequest(boolean withKeyBinding) {
        return new CreateVerificationManagement()
                .acceptedIssuerDids(null)
                .trustAnchors(null)
                .jwtSecuredAuthorizationRequest(false)
                .responseMode(ResponseModeType.DIRECT_POST)
                .dcqlQuery(defaultDcqlQuery(List.of(dcqlClaim("name")), withKeyBinding));
    }

    public static DcqlQueryDto defaultDcqlQuery(final List<DcqlClaimDto> claims, final boolean withKeyBinding) {
        final DcqlCredentialMetaDto meta = new DcqlCredentialMetaDto()
                .vctValues(List.of(DEFAULT_VCT))
                .typeValues(null);

        final DcqlCredentialDto credential = new DcqlCredentialDto()
                .id(DEFAULT_CREDENTIAL_ID)
                .format(DEFAULT_FORMAT)
                .meta(meta)
                .claims(claims)
                .requireCryptographicHolderBinding(withKeyBinding);

        return new DcqlQueryDto().credentials(List.of(credential));
    }

    public static DcqlClaimDto dcqlClaim(final String claimPath) {
        return new DcqlClaimDto()
                .id(null)
                .path(List.of(claimPath))
                .values(null);
    }

    public String createDefaultRequestString(boolean withKeyBinding) {
        try {
            return new ObjectMapper().writeValueAsString(createDefaultRequest(withKeyBinding));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
