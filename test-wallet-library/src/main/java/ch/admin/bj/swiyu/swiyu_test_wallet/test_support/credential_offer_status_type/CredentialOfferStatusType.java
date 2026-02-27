package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.credential_offer_status_type;

import lombok.Getter;

@Getter
public enum CredentialOfferStatusType {
    INIT("INIT"),
    OFFERED("Offered"),
    CANCELLED("Cancelled"),
    IN_PROGRESS("Claiming_in_Progress"),
    // Status necessary for deferred flow
    DEFERRED("Deferred"),
    READY("Ready"),
    ISSUED("Issued"),
    // status only used for renewal flow
    REQUESTED("Requested"),
    EXPIRED("Expired");

    private final String value;

    CredentialOfferStatusType(final String value) {
        this.value = value;
    }
}