package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt;

import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.TestSupportException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import org.assertj.core.api.Assertions;

import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

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

    private SignedJWT parse(String sdJwt) {
        try {
            return SignedJWT.parse(sdJwt.split("~")[0]);
        } catch (Exception e) {
            throw new AssertionError("Invalid SD-JWT", e);
        }
    }

    private Long extractStatusIndex(String sdJwt) {
        try {
            SignedJWT jwt = parse(sdJwt);

            Map<String, Object> status =
                    (Map<String, Object>) jwt.getJWTClaimsSet().getClaim("status");

            Map<String, Object> statusList =
                    (Map<String, Object>) status.get("status_list");

            Object idxObj = statusList.get("idx");

            if (!(idxObj instanceof Number number)) {
                throw new AssertionError("status_list.idx is not a number: " + idxObj);
            }

            return number.longValue();

        } catch (Exception e) {
            throw new AssertionError("Invalid status structure", e);
        }
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

    public SdJwtBatchAssert haveUniqueIssuerSignatures() {
        long distinctCount = sdJwts.stream()
                .map(this::parse)
                .map(jwt -> jwt.getSignature().toString())
                .distinct()
                .count();
        if (distinctCount != sdJwts.size()) {
            throw new AssertionError("Issuer signatures are not unique across batch");
        }
        return this;
    }

    public SdJwtBatchAssert haveUniqueHolderBindingKeys() {

        long distinctCount = sdJwts.stream()
                .map(this::parse)
                .map(jwt -> {
                    try {
                        Map<String, Object> cnf =
                                (Map<String, Object>) jwt.getJWTClaimsSet().getClaim("cnf");
                        Map<String, Object> jwk =
                                (Map<String, Object>) cnf.get("jwk");

                        return JWK.parse(jwk).computeThumbprint().toString();
                    } catch (Exception e) {
                        throw new AssertionError("Invalid cnf.jwk structure", e);
                    }
                })
                .distinct()
                .count();

        if (distinctCount != sdJwts.size()) {
            throw new AssertionError("Holder binding keys are not unique");
        }

        return this;
    }

    public SdJwtBatchAssert haveUniqueStatusListIndexes() {

        long distinctCount = sdJwts.stream()
                .map(this::extractStatusIndex)
                .distinct()
                .count();

        if (distinctCount != sdJwts.size()) {
            throw new AssertionError("Status list indexes are not unique");
        }

        return this;
    }

    public SdJwtBatchAssert haveNonSequentialStatusListIndexes() {

        List<Long> indexes = sdJwts.stream()
                .map(this::extractStatusIndex)
                .sorted()
                .toList();

        boolean sequential = true;

        for (int i = 1; i < indexes.size(); i++) {
            if (indexes.get(i) != indexes.get(i - 1) + 1) {
                sequential = false;
                break;
            }
        }

        if (sequential) {
            throw new AssertionError("Status list indexes are strictly sequential → linkability risk");
        }

        return this;
    }

    public SdJwtBatchAssert haveUniqueIat() {

        List<Long> iats = sdJwts.stream()
                .map(this::parse)
                .map(jwt -> {
                    try {
                        Date issueTime = jwt.getJWTClaimsSet().getIssueTime();
                        if (issueTime == null) {
                            throw new AssertionError("Missing iat claim");
                        }
                        return issueTime.toInstant().getEpochSecond();
                    } catch (ParseException e) {
                        throw new AssertionError(e);
                    }
                })
                .toList();

        Map<Long, Long> occurrences = iats.stream()
                .collect(Collectors.groupingBy(
                        Function.identity(),
                        Collectors.counting()
                ));

        List<String> duplicates = occurrences.entrySet().stream()
                .filter(e -> e.getValue() > 1)
                .map(e -> String.format("iat=%d (count=%d)", e.getKey(), e.getValue()))
                .toList();

        if (!duplicates.isEmpty()) {
            throw new AssertionError(
                    "iat values are not unique: " + duplicates
            );
        }

        return this;
    }

    public SdJwtBatchAssert haveUniqueCnfPublicKeys() {

    List<String> keyMaterial = sdJwts.stream()
            .map(this::parse)
            .map(jwt -> {
                try {
                    Map<String, Object> cnf =
                            (Map<String, Object>) jwt.getJWTClaimsSet().getClaim("cnf");

                    Map<String, Object> jwk =
                            (Map<String, Object>) cnf.get("jwk");

                    return jwk.get("x") + "|" + jwk.get("y");

                } catch (Exception e) {
                    throw new AssertionError("Invalid cnf structure", e);
                }
            })
            .toList();

    long distinct = keyMaterial.stream().distinct().count();

    if (distinct != keyMaterial.size()) {
        throw new AssertionError(
                "cnf public keys (x,y) are not unique across batch"
        );
    }

    return this;
}

public SdJwtBatchAssert haveNonConstantCnfKid() {

    List<String> kids = sdJwts.stream()
            .map(this::parse)
            .map(jwt -> {
                try {
                    Map<String, Object> cnf =
                            (Map<String, Object>) jwt.getJWTClaimsSet().getClaim("cnf");

                    Map<String, Object> jwk =
                            (Map<String, Object>) cnf.get("jwk");

                    Object kid = jwk.get("kid");
                    return kid == null ? null : kid.toString();

                } catch (Exception e) {
                    throw new AssertionError("Invalid cnf structure", e);
                }
            })
            .filter(Objects::nonNull)
            .toList();

    if (!kids.isEmpty()) {
        long distinct = kids.stream().distinct().count();
        if (distinct == 1) {
            throw new AssertionError(
                    "cnf.jwk.kid is constant across batch → correlation signal: " + kids.get(0)
            );
        }
    }

    return this;
}

    public SdJwtBatchAssert areNotLinkable() {
        throw new TestSupportException("Not implemented yet");
    }


}

