package ch.admin.bj.swiyu.swiyu_test_wallet.environment;

import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import org.junit.jupiter.api.ClassDescriptor;
import org.junit.jupiter.api.ClassOrderer;
import org.junit.jupiter.api.ClassOrdererContext;
import org.junit.jupiter.api.Tag;

import java.util.Comparator;
import java.util.List;
import java.util.Set;

import static java.util.stream.Collectors.joining;

/**
 * Groups E2E classes by their declared environment so consecutive classes can reuse running component variants.
 *
 * <p>Ordering only reads configuration annotations: container ownership, per-class preparation and method order remain
 * unchanged. Variant names are normalized for comparison without changing the primary component declared by a class.
 * Version-regression classes retain their discovery positions and transition lifecycle, including when JUnit discovers
 * them before applying the standard suite's tag filter.
 */
public final class EnvironmentClassOrderer implements ClassOrderer {

    private static final Comparator<SwiyuEnvironmentSelection> ENVIRONMENT_ORDER = Comparator
            .comparing((SwiyuEnvironmentSelection selection) -> variantNames(selection.issuers()))
            .thenComparing(selection -> variantNames(selection.verifiers()))
            .thenComparing(SwiyuEnvironmentSelection::keycloak)
            .thenComparing(SwiyuEnvironmentSelection::hsm);

    private static final Comparator<ClassDescriptor> CLASS_ORDER = Comparator
            .comparing((ClassDescriptor descriptor) -> SwiyuEnvironmentSelection.from(descriptor.getTestClass()),
                    ENVIRONMENT_ORDER)
            .thenComparing(descriptor -> descriptor.getTestClass().getName());

    @Override
    public void orderClasses(final ClassOrdererContext context) {
        groupStandardClasses(context.getClassDescriptors());
    }

    private static <T extends ClassDescriptor> void groupStandardClasses(final List<T> descriptors) {
        final var grouped = descriptors.stream()
                .filter(descriptor -> !isVersionRegression(descriptor))
                .sorted(CLASS_ORDER)
                .toList()
                .iterator();

        final var positions = descriptors.listIterator();
        while (positions.hasNext()) {
            if (!isVersionRegression(positions.next())) {
                positions.set(grouped.next());
            }
        }
    }

    private static boolean isVersionRegression(final ClassDescriptor descriptor) {
        return descriptor.findRepeatableAnnotations(Tag.class).stream()
                .anyMatch(tag -> ReportingTags.VERSION_REGRESSION.equals(tag.value()));
    }

    private static String variantNames(final Set<? extends Enum<?>> variants) {
        return variants.stream()
                .map(Enum::name)
                .sorted()
                .collect(joining(","));
    }
}
