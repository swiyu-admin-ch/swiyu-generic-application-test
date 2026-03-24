package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import lombok.Builder;
import lombok.Data;

import java.security.KeyPair;

@Builder
@Data
public class IssuerConfig {

    private String mockServerUri;
    private String swiyuPartnerId;
    private String issuerServiceUrl;
    private String issuerRegistryEntry;
    private String issuerDid;
    private String issuerDidLog;
    private String issuerAssertKeyId;
    private String issuerAuthKeyId;
    private String issuerAssertKeyPemString;
    private String issuerAuthKeyPemString;

    private KeyPair keyPair;
}
