package ch.admin.bj.swiyu.swiyu_test_wallet.environment;

import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting.ReportingTags;
import org.junit.jupiter.api.ClassDescriptor;
import org.junit.jupiter.api.ClassOrdererContext;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class EnvironmentClassOrdererTest {

    private final EnvironmentClassOrderer orderer = new EnvironmentClassOrderer();

    @Test
    void classes_whenEnvironmentsAreInterleaved_thenCompatibleClassesAreConsecutive() {
        final var descriptors = descriptors(DefaultZ.class, Strict.class, DefaultA.class, Cached.class);

        orderer.orderClasses(context(descriptors));

        assertThat(classes(descriptors))
                .containsExactly(Cached.class, DefaultA.class, DefaultZ.class, Strict.class);
    }

    @Test
    void classes_whenVariantDeclarationsHaveDifferentOrder_thenGroupWithoutChangingPrimaryComponents() {
        final var descriptors = descriptors(SignedPrimary.class, Strict.class, DefaultPrimary.class);

        orderer.orderClasses(context(descriptors));

        assertThat(classes(descriptors))
                .containsExactly(DefaultPrimary.class, SignedPrimary.class, Strict.class);
        assertThat(SwiyuEnvironmentSelection.from(DefaultPrimary.class).primaryIssuer())
                .isEqualTo(IssuerVariant.DEFAULT);
        assertThat(SwiyuEnvironmentSelection.from(SignedPrimary.class).primaryIssuer())
                .isEqualTo(IssuerVariant.SIGNED_METADATA);
        assertThat(SwiyuEnvironmentSelection.from(DefaultPrimary.class).primaryVerifier())
                .isEqualTo(VerifierVariant.DEFAULT);
        assertThat(SwiyuEnvironmentSelection.from(SignedPrimary.class).primaryVerifier())
                .isEqualTo(VerifierVariant.CACHED);
    }

    @Test
    void classes_whenVerifiersOrSharedServicesDiffer_thenKeepDistinctEnvironmentGroups() {
        final var descriptors = descriptors(Keycloak.class, DefaultA.class, CachedVerifier.class, SoftHsm.class);

        orderer.orderClasses(context(descriptors));

        assertThat(classes(descriptors))
                .containsExactly(CachedVerifier.class, DefaultA.class, SoftHsm.class, Keycloak.class);
    }

    @Test
    void classes_whenDiscoveryOrderChanges_thenProduceTheSameOrderAndPreserveEveryClass() {
        final var original = descriptors(DefaultZ.class, Strict.class, DefaultA.class, CachedVerifier.class);
        final var expected = List.of(CachedVerifier.class, DefaultA.class, DefaultZ.class, Strict.class);
        final var shuffled = new ArrayList<>(original);
        final var random = new Random(1403);

        for (int attempt = 0; attempt < 5; attempt++) {
            Collections.shuffle(shuffled, random);

            orderer.orderClasses(context(shuffled));

            assertThat(classes(shuffled))
                    .containsExactlyElementsOf(expected);
        }
    }

    @Test
    void classes_whenVersionRegressionIsDiscoveredAlongsideStandardTests_thenKeepItsPositionAndGroupTheOthers() {
        final var descriptors = descriptors(Strict.class, VersionRegression.class, DefaultA.class);

        orderer.orderClasses(context(descriptors));

        assertThat(classes(descriptors))
                .containsExactly(DefaultA.class, VersionRegression.class, Strict.class);
    }

    @Test
    void classes_whenOnlyVersionRegressionsAreSelected_thenPreserveTheDiscoveredOrder() {
        final var descriptors = descriptors(VersionRegressionZ.class, VersionRegression.class);

        orderer.orderClasses(context(descriptors));

        assertThat(classes(descriptors))
                .containsExactly(VersionRegressionZ.class, VersionRegression.class);
    }

    @Test
    void classes_whenSelectionIsEmptyOrTargeted_thenKeepTheSelection() {
        final var empty = new ArrayList<ClassDescriptor>();
        final var targeted = descriptors(Strict.class);

        orderer.orderClasses(context(empty));
        orderer.orderClasses(context(targeted));

        assertThat(empty)
                .isEmpty();
        assertThat(classes(targeted))
                .containsExactly(Strict.class);
    }

    private static List<ClassDescriptor> descriptors(final Class<?>... testClasses) {
        final var descriptors = new ArrayList<ClassDescriptor>();
        for (final Class<?> testClass : testClasses) {
            final ClassDescriptor descriptor = mock(ClassDescriptor.class);
            when(descriptor.getTestClass()).thenAnswer(invocation -> testClass);
            when(descriptor.findRepeatableAnnotations(Tag.class))
                    .thenReturn(Arrays.asList(testClass.getAnnotationsByType(Tag.class)));
            descriptors.add(descriptor);
        }
        return descriptors;
    }

    private static ClassOrdererContext context(final List<ClassDescriptor> descriptors) {
        final ClassOrdererContext context = mock(ClassOrdererContext.class);
        when(context.getClassDescriptors()).thenAnswer(invocation -> descriptors);
        return context;
    }

    private static List<Class<?>> classes(final List<ClassDescriptor> descriptors) {
        return descriptors.stream()
                .map(ClassDescriptor::getTestClass)
                .toList();
    }

    private static final class DefaultA { }

    private static final class DefaultZ { }

    @UseIssuers(IssuerVariant.STRICT)
    private static final class Strict { }

    @UseIssuers(IssuerVariant.CACHED)
    private static final class Cached { }

    @UseIssuers({IssuerVariant.DEFAULT, IssuerVariant.SIGNED_METADATA})
    @UseVerifiers({VerifierVariant.DEFAULT, VerifierVariant.CACHED})
    private static final class DefaultPrimary { }

    @UseIssuers({IssuerVariant.SIGNED_METADATA, IssuerVariant.DEFAULT})
    @UseVerifiers({VerifierVariant.CACHED, VerifierVariant.DEFAULT})
    private static final class SignedPrimary { }

    @UseVerifiers(VerifierVariant.CACHED)
    private static final class CachedVerifier { }

    @UseSharedServices(keycloak = true)
    private static final class Keycloak { }

    @UseSharedServices(hsm = true)
    private static final class SoftHsm { }

    @Tag(ReportingTags.VERSION_REGRESSION)
    private static final class VersionRegression { }

    @Tag(ReportingTags.VERSION_REGRESSION)
    private static final class VersionRegressionZ { }
}
