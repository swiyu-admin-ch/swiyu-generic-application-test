package ch.admin.bj.swiyu.swiyu_test_wallet.junit;

import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.Arrays;

public final class DisableIfImageTagExtension implements ExecutionCondition {

    private static final ConditionEvaluationResult ENABLED =
            ConditionEvaluationResult.enabled("Image tag condition not met");

    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(
            final ExtensionContext context
    ) {
        final DisableIfImageTag annotation = findAnnotation(context);
        if (annotation == null) {
            return ENABLED;
        }

        final ApplicationContext appContext =
                SpringExtension.getApplicationContext(context);
        final Environment env = appContext.getEnvironment();

        final String issuerTag =
                env.getProperty("application.issuer.image-tag");
        final String verifierTag =
                env.getProperty("application.verifier.image-tag");

        if (matches(issuerTag, annotation.issuer())) {
            return disabled("issuer", issuerTag, annotation);
        }

        if (matches(verifierTag, annotation.verifier())) {
            return disabled("verifier", verifierTag, annotation);
        }

        return ENABLED;
    }

    private static DisableIfImageTag findAnnotation(final ExtensionContext context) {
        return context.getElement()
                .map(el -> el.getAnnotation(DisableIfImageTag.class))
                .orElse(null);
    }

    private static boolean matches(
            final String actualTag,
            final String[] forbiddenTags
    ) {
        return actualTag != null
                && Arrays.asList(forbiddenTags).contains(actualTag);
    }

    private static ConditionEvaluationResult disabled(
            final String component,
            final String tag,
            final DisableIfImageTag annotation
    ) {
        final String reason = annotation.reason().isBlank()
                ? "Disabled because " + component + " image-tag is '" + tag + "'"
                : annotation.reason();

        return ConditionEvaluationResult.disabled(reason);
    }
}
