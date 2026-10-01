package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares how the Wallet behaves in every test of a class, like {@code @UseIssuers} declares the Credential Issuers.
 * {@code BaseTest} builds a fresh {@link Wallet} from it before each test, so no test inherits a setting from another.
 * A test that needs something else for itself changes its own wallet.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface UseWallet {

    /** Send a DPoP proof on token, credential, and deferred requests. */
    boolean dpop() default false;

    /** Encrypt Credential Requests and Authorization Responses. */
    boolean encryption() default false;

    /** Ask for signed Credential Issuer Metadata. */
    boolean signedMetadata() default false;
}
