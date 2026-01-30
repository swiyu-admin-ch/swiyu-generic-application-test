package ch.admin.bj.swiyu.swiyu_test_wallet.junit;

import org.junit.jupiter.api.extension.ExtendWith;

import java.lang.annotation.*;

@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(DisableIfImageTagExtension.class)
public @interface DisableIfImageTag {

    String[] issuer() default {};

    String[] verifier() default {};

    String reason() default "";
}
