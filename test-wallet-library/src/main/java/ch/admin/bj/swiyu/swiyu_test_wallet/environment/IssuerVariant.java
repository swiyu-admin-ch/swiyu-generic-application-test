package ch.admin.bj.swiyu.swiyu_test_wallet.environment;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;

public enum IssuerVariant {
    DEFAULT("default", false, null, null, null, null),
    STRICT("strict", false, true, false, true, false),
    SIGNED_METADATA("signed_metadata", false, null, true, null, null),
    COMPLETE("complete", false, true, true, false, true),
    ENCRYPTION("encryption", false, false, true, false, true),
    HSM("hsm", true, null, null, null, null),
    MANAGEMENT_KEYCLOAK("management_keycloak", false, null, false, false, null);

    private final String surname;
    private final boolean hsm;
    private final Boolean enforceDpop;
    private final Boolean signedMetadata;
    private final Boolean jwtAuth;
    private final Boolean encryptionEnforce;

    IssuerVariant(
            final String surname,
            final boolean hsm,
            final Boolean enforceDpop,
            final Boolean signedMetadata,
            final Boolean jwtAuth,
            final Boolean encryptionEnforce) {
        this.surname = surname;
        this.hsm = hsm;
        this.enforceDpop = enforceDpop;
        this.signedMetadata = signedMetadata;
        this.jwtAuth = jwtAuth;
        this.encryptionEnforce = encryptionEnforce;
    }

    public boolean requiresHsm() {
        return hsm;
    }

    public boolean requiresKeycloak() {
        return this == MANAGEMENT_KEYCLOAK;
    }

    public IssuerImageConfig imageConfig(final IssuerImageConfig template) {
        final IssuerImageConfig config = copy(template);
        config.setSurname(surname);
        config.setEnableHsm(hsm);
        if (enforceDpop != null) {
            config.setEnforceDpop(enforceDpop);
        }
        if (signedMetadata != null) {
            config.setSignedMetadata(signedMetadata);
        }
        if (jwtAuth != null) {
            config.setEnableJwtAuth(jwtAuth);
        }
        if (encryptionEnforce != null) {
            config.setEncryptionEnforce(encryptionEnforce);
        }
        return config;
    }

    private static IssuerImageConfig copy(final IssuerImageConfig source) {
        final IssuerImageConfig target = new IssuerImageConfig();
        target.setBaseImage(source.getBaseImage());
        target.setImageTag(source.getImageTag());
        target.setSurname(source.getSurname());
        target.setEnforceDpop(source.isEnforceDpop());
        target.setSignedMetadata(source.isSignedMetadata());
        target.setEnableJwtAuth(source.isEnableJwtAuth());
        target.setEncryptionEnforce(source.isEncryptionEnforce());
        target.setEnableHsm(source.isEnableHsm());
        target.setHsmUser(source.getHsmUser());
        target.setHsmPassword(source.getHsmPassword());
        target.setHsmUserPin(source.getHsmUserPin());
        target.setHsmKeyId(source.getHsmKeyId());
        target.setHsmKeyPin(source.getHsmKeyPin());
        target.setHsmStatusKeyId(source.getHsmStatusKeyId());
        target.setHsmStatusKeyPin(source.getHsmStatusKeyPin());
        return target;
    }
}
