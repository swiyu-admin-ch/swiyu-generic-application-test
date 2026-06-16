package ch.admin.bj.swiyu.swiyu_test_wallet.environment;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface UseSharedServices {
    boolean keycloak() default false;
    boolean hsm() default false;
}
