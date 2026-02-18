package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt;

import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.TestSupportException;
import org.assertj.core.api.Assertions;

import java.util.List;
import java.util.Map;

public final class SdJwtBatchAssert {

    private final List<String> sdJwts;

    private SdJwtBatchAssert(final List<String> sdJwts) {
        this.sdJwts = sdJwts;
    }

    public static SdJwtBatchAssert assertThat(
            final List<String> sdJwts
    ) {
        return new SdJwtBatchAssert(sdJwts);
    }

    public SdJwtBatchAssert allHaveExactlyInAnyOrderDisclosures(
            final Map<String, Object> expectedDisclosures
    ) {
        Assertions.assertThat(sdJwts)
                .as("SD-JWT batch must not be empty")
                .isNotEmpty();

        for (int i = 0; i < sdJwts.size(); i++) {
            SdJwtAssert.assertThat(sdJwts.get(i))
                    .hasExactlyInAnyOrderDisclosures(expectedDisclosures);
        }

        return this;
    }

    public SdJwtBatchAssert hasBatchSize(final int expectedSize) {
        Assertions.assertThat(sdJwts)
                .as("SD-JWT batch size")
                .hasSize(expectedSize);

        return this;
    }

    public SdJwtBatchAssert areUnique() {
        Assertions.assertThat(sdJwts)
                .as("SD-JWT batch credentials must be unique")
                .doesNotHaveDuplicates();

        return this;
    }

    public SdJwtBatchAssert areNotLinkable() {
        throw new TestSupportException("Not implemented yet");
    }


}

