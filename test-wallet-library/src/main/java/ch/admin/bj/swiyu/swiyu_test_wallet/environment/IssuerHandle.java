package ch.admin.bj.swiyu.swiyu_test_wallet.environment;

import ch.admin.bj.swiyu.gen.issuer.model.StatusList;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.ManagementAuthConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.BusinessIssuer;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuanceService;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.ServiceLocationContext;
import org.testcontainers.containers.GenericContainer;

import java.security.PrivateKey;

public record IssuerHandle(
        IssuerVariant variant,
        IssuerConfig config,
        IssuerImageConfig imageConfig,
        GenericContainer<?> container,
        BusinessIssuer manager,
        IssuanceService issuanceService,
        ServiceLocationContext serviceLocation,
        StatusList statusList,
        PrivateKey jwtKey,
        PrivateKey unauthenticatedJwtKey,
        String keyId,
        ManagementAuthConfig managementAuthConfig,
        String managementAccessToken
) {
    public String serviceUrl() {
        return config.getIssuerServiceUrl();
    }
}
