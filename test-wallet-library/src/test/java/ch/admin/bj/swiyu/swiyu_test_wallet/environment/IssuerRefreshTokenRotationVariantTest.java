package ch.admin.bj.swiyu.swiyu_test_wallet.environment;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class IssuerRefreshTokenRotationVariantTest {
    @Test
    void disablingRefreshTokenRotation_shouldNotChangeOtherVariantsOrTheirTemplate() {
        final var template = new IssuerImageConfig();
        final var withoutRotation = IssuerVariant.NO_REFRESH_TOKEN_ROTATION.imageConfig(template);

        assertThat(withoutRotation.isAllowRefreshTokenRotation())
                .isFalse();
        assertThat(withoutRotation.isEnforceDpop())
                .isTrue();
        assertThat(template.isAllowRefreshTokenRotation())
                .isTrue();
        for (final IssuerVariant variant : IssuerVariant.values()) {
            if (variant != IssuerVariant.NO_REFRESH_TOKEN_ROTATION) {
                assertThat(variant.imageConfig(template).isAllowRefreshTokenRotation())
                        .as("Refresh rotation of %s", variant)
                        .isTrue();
            }
        }
    }
}
