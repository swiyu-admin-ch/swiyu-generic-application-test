package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import lombok.experimental.UtilityClass;

import java.net.URI;

@UtilityClass
public class EnvironmentConfig {

    public static IssuerConfig createIssuerConfig(final URI identifierRegistryUrl, final boolean enableHsm, final String hsmTokenDir) {
        return IssuerConfig.createIssuerConfig(identifierRegistryUrl, enableHsm, hsmTokenDir);
    }

    public static TrustConfig createTrustConfig(URI identifierRegistryUrl) {
        return TrustConfig.createTrustDid(identifierRegistryUrl);
    }
}