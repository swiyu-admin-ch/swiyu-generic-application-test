package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;

public sealed interface VerificationRequestObject
        permits VerificationRequestObject.Signed,
        VerificationRequestObject.Unsigned {

    record Signed(String jwt) implements VerificationRequestObject {}
    record Unsigned(RequestObject requestObject) implements VerificationRequestObject {}
}

