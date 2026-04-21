package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt;

import com.jayway.jsonpath.JsonPath;

import lombok.extern.slf4j.Slf4j;

import org.assertj.core.api.Assertions;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
public final class SdJwtAssert {

    private final String headerJson;
    private final String payloadJson;
    private final List<String> disclosures;
    private final Optional<String> keyBindingJwt;

    private SdJwtAssert(final String sdJwt) {
        this.headerJson = SdJwtParser.header(sdJwt);
        this.payloadJson = SdJwtParser.payload(sdJwt);
        this.disclosures = SdJwtParser.disclosures(sdJwt);
        this.keyBindingJwt = SdJwtParser.keyBindingJwt(sdJwt);
    }

    public static SdJwtAssert assertThat(final String sdJwt) {
        final SdJwtAssert sdJwtAssert = new SdJwtAssert(sdJwt);
        log.debug(String.format("SdJwt [%s]", sdJwt));
        log.debug(String.format("\tHeaderJson [%s]", sdJwtAssert.headerJson));
        log.debug(String.format("\tPayloadJson [%s]", sdJwtAssert.payloadJson));
        log.debug(String.format("\tDisclosures [%s]", sdJwtAssert.disclosures));
        log.debug(String.format("\tKeyBindingJwt [%s]", sdJwtAssert.keyBindingJwt));
        return sdJwtAssert;
    }

    public SdJwtAssert hasHeaderAlg(final String expectedAlg) {
        final String alg = JsonPath.read(headerJson, "$.alg");

        Assertions.assertThat(alg)
                .as("sd-jwt header.alg")
                .isEqualTo(expectedAlg);

        return this;
    }

    public SdJwtAssert hasType(final String expectedTyp) {
        final String typ = JsonPath.read(headerJson, "$.typ");

        Assertions.assertThat(typ)
                .as("sd-jwt header.typ")
                .isEqualTo(expectedTyp);

        return this;
    }

    public SdJwtAssert hasPayloadClaim(
            final String claim,
            final Object expectedValue
    ) {
        final Object value =
                JsonPath.read(payloadJson, "$." + claim);

        Assertions.assertThat(value)
                .as("sd-jwt payload.%s", claim)
                .isEqualTo(expectedValue);

        return this;
    }

    public SdJwtAssert hasSdAlgorithm(final String expectedAlg) {
        final String sdAlg =
                JsonPath.read(payloadJson, "$._sd_alg");

        Assertions.assertThat(sdAlg)
                .as("sd-jwt payload._sd_alg")
                .isEqualTo(expectedAlg);

        return this;
    }

    public SdJwtAssert hasDisclosure(
            final String claimName,
            final Object expectedValue
    ) {
        final boolean found = disclosures.stream()
                .anyMatch(disclosureJson -> {
                    final List<?> parts =
                            JsonPath.read(disclosureJson, "$");
                    return parts.size() >= 3
                            && claimName.equals(parts.get(1))
                            && expectedValue.equals(parts.get(2));
                });

        Assertions.assertThat(found)
                .as("Disclosure for claim [%s] with expected value [%s]", claimName, expectedValue)
                .isTrue();

        return this;
    }

    public SdJwtAssert hasDisclosure(final String claimName) {
        final boolean found = disclosures.stream()
                .anyMatch(disclosureJson -> {
                    final List<?> parts =
                            JsonPath.read(disclosureJson, "$");
                    return parts.size() >= 2
                            && claimName.equals(parts.get(1));
                });

        Assertions.assertThat(found)
                .as("Disclosure for claim '%s'", claimName)
                .isTrue();

        return this;
    }

    public SdJwtAssert hasNotDisclosure(final String claimName) {
        final boolean found = disclosures.stream()
                .anyMatch(disclosureJson -> {
                    final List<?> parts =
                            JsonPath.read(disclosureJson, "$");
                    return parts.size() >= 2
                            && claimName.equals(parts.get(1));
                });

        Assertions.assertThat(found)
                .as("Disclosure for claim '%s' should not exist", claimName)
                .isFalse();

        return this;
    }

    public SdJwtAssert hasExactlyInAnyOrderDisclosures(
            final Map<String, Object> expectedDisclosures
    ) {
        final Map<String, Object> actualDisclosures =
                disclosures.stream()
                        .map(disclosureJson -> {
                            final List<?> parts =
                                    JsonPath.read(disclosureJson, "$");

                            final String key = (String) parts.get(1);
                            final Object value = parts.get(2);

                            return Map.entry(key, value);
                        })
                        .collect(Collectors.toMap(
                                Map.Entry::getKey,
                                Map.Entry::getValue
                        ));

        Assertions.assertThat(actualDisclosures)
                .as("Exact SD-JWT disclosures")
                .containsExactlyInAnyOrderEntriesOf(expectedDisclosures);

        return this;
    }


    public SdJwtAssert hasKeyBindingAudience(final String expectedAud) {
        final String kbJwt =
                keyBindingJwt.orElseThrow(
                        () -> new AssertionError("Expected key binding JWT but none was found")
                );

        final String kbPayloadJson =
                SdJwtParser.payload(kbJwt);

        final String aud =
                JsonPath.read(kbPayloadJson, "$.aud");

        Assertions.assertThat(aud)
                .as("sd-jwt key binding payload.aud")
                .isEqualTo(expectedAud);

        return this;
    }
}
