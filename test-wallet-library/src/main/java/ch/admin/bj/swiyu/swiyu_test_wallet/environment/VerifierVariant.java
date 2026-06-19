package ch.admin.bj.swiyu.swiyu_test_wallet.environment;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;

public enum VerifierVariant {
    DEFAULT("default", false),
    HSM("hsm", true),
    MANAGEMENT_KEYCLOAK("management_keycloak", false);

    private final String surname;
    private final boolean hsm;

    VerifierVariant(final String surname, final boolean hsm) {
        this.surname = surname;
        this.hsm = hsm;
    }

    public boolean requiresHsm() {
        return hsm;
    }

    public boolean requiresKeycloak() {
        return this == MANAGEMENT_KEYCLOAK;
    }

    public VerifierImageConfig imageConfig(final VerifierImageConfig template) {
        final VerifierImageConfig config = copy(template);
        config.setSurname(surname);
        config.setEnableHsm(hsm);
        return config;
    }

    private static VerifierImageConfig copy(final VerifierImageConfig source) {
        final VerifierImageConfig target = new VerifierImageConfig();
        target.setBaseImage(source.getBaseImage());
        target.setImageTag(source.getImageTag());
        target.setSwiyuPartnerId(source.getSwiyuPartnerId());
        target.setSurname(source.getSurname());
        target.setEnableHsm(source.isEnableHsm());
        target.setHsmUser(source.getHsmUser());
        target.setHsmPassword(source.getHsmPassword());
        target.setHsmUserPin(source.getHsmUserPin());
        target.setHsmKeyId(source.getHsmKeyId());
        target.setHsmKeyPin(source.getHsmKeyPin());
        return target;
    }
}
