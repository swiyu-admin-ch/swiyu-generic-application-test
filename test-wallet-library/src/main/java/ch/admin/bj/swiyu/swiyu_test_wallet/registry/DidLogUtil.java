package ch.admin.bj.swiyu.swiyu_test_wallet.registry;

import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext;
import ch.admin.bj.swiyu.didtoolbox.model.DidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.model.TdwDidLogMetaPeeker;
import ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import lombok.experimental.UtilityClass;

import java.net.URI;
import java.security.interfaces.ECPublicKey;
import java.util.Set;

@UtilityClass
public class DidLogUtil {

    public static String createDidLog(ECPublicKey authenticationKey, ECPublicKey assertionMethodKey, URI identifierRegistryUrl) {

        var suite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();

        try {
            return DidLogCreatorContext.builder(DidMethodEnum.TDW_0_3, suite)
                    .authentications(Set.of(VerificationMethod.of("auth-key-01", authenticationKey)))
                    .assertionMethods(Set.of(VerificationMethod.of("assert-key-01", assertionMethodKey)))
                    .build()
                    .create(identifierRegistryUrl.toURL());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String getDidFromDidLog(String didLog) {
        try {
            return TdwDidLogMetaPeeker.peek(didLog).getDidDoc().getId();
        } catch (DidLogMetaPeekerException e) {
            throw new IllegalStateException(e);
        }
    }
}
