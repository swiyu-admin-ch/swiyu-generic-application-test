package ch.admin.bj.swiyu.swiyu_test_wallet.registry;

import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext;
import ch.admin.bj.swiyu.didtoolbox.model.DidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod;
import ch.admin.bj.swiyu.didtoolbox.model.WebVerifiableHistoryDidLogMetaPeeker;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import com.nimbusds.jose.jwk.JWK;
import lombok.experimental.UtilityClass;

import java.net.URI;
import java.security.interfaces.ECPublicKey;
import java.util.Set;

@UtilityClass
public class DidLogUtil {

    public static String createDidLog(ECPublicKey authenticationKey, ECPublicKey assertionMethodKey, URI identifierRegistryUrl) {
        return createDidLog(
                VerificationMethod.of("auth-key-01", authenticationKey),
                VerificationMethod.of("assert-key-01", assertionMethodKey),
                identifierRegistryUrl
        );
    }

    public static String createDidLog(JWK authenticationKey, JWK assertionMethodKey, URI identifierRegistryUrl) {
        try {
            return createDidLog(
                    VerificationMethod.of("auth-key-01", authenticationKey.toPublicJWK().toJSONString()),
                    VerificationMethod.of("assert-key-01", assertionMethodKey.toPublicJWK().toJSONString()),
                    identifierRegistryUrl
            );
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String createDidLog(
            VerificationMethod authenticationMethod,
            VerificationMethod assertionMethod,
            URI identifierRegistryUrl) {
        var suite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();

        try {
            return DidLogCreatorContext.builder(DidMethodEnum.WEBVH_1_0, suite)
                    .authentications(Set.of(authenticationMethod))
                    .assertionMethods(Set.of(assertionMethod))
                    .build()
                    .create(identifierRegistryUrl.toURL());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String getDidFromDidLog(String didLog) {
        try {
            return WebVerifiableHistoryDidLogMetaPeeker.peek(didLog).getDidDoc().getId();
        } catch (DidLogMetaPeekerException e) {
            throw new IllegalStateException(e);
        }
    }
}
