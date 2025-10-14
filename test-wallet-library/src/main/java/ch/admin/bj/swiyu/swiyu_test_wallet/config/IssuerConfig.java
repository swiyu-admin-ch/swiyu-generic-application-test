package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class IssuerConfig {

    private String mockServerUri = "https://%s:%s".formatted("mockserver", 1080);
    private String swiyuPartnerId;
    private String issuerServiceUrl;
    private String issuerRegistryEntry;
    private String issuerDid;
    private String issuerDidLog;
    private String issuerAssertKeyId;
    private String issuerAuthKeyId;
    private String issuerAssertKeyPemString;
    private String issuerAuthKeyPemString;
}
