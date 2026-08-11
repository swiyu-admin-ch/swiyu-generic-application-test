package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.sdjwt;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import org.assertj.core.api.Assertions;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

public final class SdJwtBatchAssert {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final Set<String> NON_DISCLOSABLE_CLAIMS = Set.of(
            "iss",
            "nbf",
            "exp",
            "cnf",
            "vct",
            "vct#integrity",
            "status",
            "_sd",
            "_sd_alg",
            "sd_hash",
            "..."
    );

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

    private List<Object> decodeDisclosure(String rawDisclosure) {
        try {
            final byte[] decoded = Base64.getUrlDecoder().decode(rawDisclosure);
            return OBJECT_MAPPER.readValue(decoded, new TypeReference<List<Object>>() {});
        } catch (Exception e) {
            throw new AssertionError("Invalid SD-JWT disclosure", e);
        }
    }

    private String extractDisclosureSalt(String rawDisclosure) {
        final List<Object> disclosure = decodeDisclosure(rawDisclosure);
        if (disclosure.isEmpty() || !(disclosure.getFirst() instanceof String salt) || salt.isBlank()) {
            throw new AssertionError("Disclosure salt is missing or invalid: " + disclosure);
        }
        return salt;
    }

    private String extractDisclosureClaimName(String rawDisclosure) {
        final List<Object> disclosure = decodeDisclosure(rawDisclosure);
        if (disclosure.size() == 3 && disclosure.get(1) instanceof String claimName) {
            return claimName;
        }
        return null;
    }

    private String disclosureDigest(String rawDisclosure) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] hash = digest.digest(rawDisclosure.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("SHA-256 is not available", e);
        }
    }

    private List<String> disclosureDigests(String sdJwt) {
        return SdJwtParser.rawDisclosures(sdJwt).stream()
                .map(this::disclosureDigest)
                .toList();
    }

    private List<String> referencedDisclosureDigests(String sdJwt) {
        final List<String> digests = new ArrayList<>();
        try {
            digests.addAll(extractDisclosureDigests(parse(sdJwt).getJWTClaimsSet().toJSONObject()));
        } catch (ParseException e) {
            throw new AssertionError("Invalid SD-JWT claims", e);
        }

        SdJwtParser.rawDisclosures(sdJwt).stream()
                .map(this::decodeDisclosure)
                .forEach(disclosure -> digests.addAll(extractDisclosureDigests(disclosure)));

        return digests;
    }

    private List<String> extractDisclosureDigests(Object value) {
        final List<String> digests = new ArrayList<>();

        if (value instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                final Object key = entry.getKey();
                final Object child = entry.getValue();

                if ("_sd".equals(key) && child instanceof List<?> sdDigests) {
                    sdDigests.stream()
                            .filter(String.class::isInstance)
                            .map(String.class::cast)
                            .forEach(digests::add);
                } else if ("...".equals(key) && child instanceof String digest) {
                    digests.add(digest);
                } else {
                    digests.addAll(extractDisclosureDigests(child));
                }
            }
        } else if (value instanceof List<?> list) {
            list.forEach(element -> digests.addAll(extractDisclosureDigests(element)));
        }

        return digests;
    }

    private Long extractStatusIndex(String sdJwt) {
        try {
            final SignedJWT jwt = parse(sdJwt);

            final Map<String, Object> status =
                    (Map<String, Object>) jwt.getJWTClaimsSet().getClaim("status");

            final Map<String, Object> statusList =
                    (Map<String, Object>) status.get("status_list");

            final Object idxObj = statusList.get("idx");

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

    public SdJwtBatchAssert haveUniqueDisclosureSalts() {
        final List<String> salts = sdJwts.stream()
                .flatMap(sdJwt -> SdJwtParser.rawDisclosures(sdJwt).stream())
                .map(this::extractDisclosureSalt)
                .toList();

        Assertions.assertThat(salts)
                .as("SD-JWT disclosure salts must not be reused")
                .doesNotHaveDuplicates();

        return this;
    }

    public SdJwtBatchAssert haveUniqueDisclosureDigests() {
        final List<String> digests = sdJwts.stream()
                .flatMap(sdJwt -> disclosureDigests(sdJwt).stream())
                .toList();

        Assertions.assertThat(digests)
                .as("SD-JWT disclosure digests must not be reused")
                .doesNotHaveDuplicates();

        return this;
    }

    public SdJwtBatchAssert haveDisclosuresBoundToPayloadDigests() {
        for (int i = 0; i < sdJwts.size(); i++) {
            final String sdJwt = sdJwts.get(i);

            Assertions.assertThat(disclosureDigests(sdJwt))
                    .as("SD-JWT[%d] disclosures must match _sd digest references", i)
                    .containsExactlyInAnyOrderElementsOf(referencedDisclosureDigests(sdJwt));
        }

        return this;
    }

    public SdJwtBatchAssert haveNoNonDisclosableClaimsInDisclosures() {
        final List<String> nonDisclosableClaims = sdJwts.stream()
                .flatMap(sdJwt -> SdJwtParser.rawDisclosures(sdJwt).stream())
                .map(this::extractDisclosureClaimName)
                .filter(Objects::nonNull)
                .filter(NON_DISCLOSABLE_CLAIMS::contains)
                .toList();

        Assertions.assertThat(nonDisclosableClaims)
                .as("SD-JWT disclosures must not contain non-selectively disclosable claims")
                .isEmpty();

        return this;
    }

    public SdJwtBatchAssert haveUniqueIssuerSignatures() {
        final long distinctCount = sdJwts.stream()
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
        final long distinctCount = sdJwts.stream()
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
        final long distinctCount = sdJwts.stream()
                .map(this::extractStatusIndex)
                .distinct()
                .count();

        if (distinctCount != sdJwts.size()) {
            throw new AssertionError("Status list indexes are not unique");
        }

        return this;
    }

    public SdJwtBatchAssert haveNonSequentialStatusListIndexes() {
        final List<Long> indexes = sdJwts.stream()
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
        final List<Long> iats = sdJwts.stream()
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

        final Map<Long, Long> occurrences = iats.stream()
                .collect(Collectors.groupingBy(
                        Function.identity(),
                        Collectors.counting()
                ));

        final List<String> duplicates = occurrences.entrySet().stream()
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
        final List<String> keyMaterial = sdJwts.stream()
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

        final long distinct = keyMaterial.stream().distinct().count();

        if (distinct != keyMaterial.size()) {
            throw new AssertionError(
                    "cnf public keys (x,y) are not unique across batch"
            );
        }

        return this;
    }

    public SdJwtBatchAssert haveNonConstantCnfKid() {
        final List<String> kids = sdJwts.stream()
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

    public SdJwtBatchAssert haveDayRoundedIat() {
        final List<Long> iats = sdJwts.stream()
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

        final long distinct = iats.stream().distinct().count();
        if (distinct != 1) {
            throw new AssertionError("iat values differ across batch: " + iats);
        }

        final long iat = iats.getFirst();

        final long secondsInDay = 24 * 60 * 60;
        if (iat % secondsInDay != 0) {
            throw new AssertionError(
                    "iat is not rounded to beginning of day (00:00:00 UTC). Value: " + iat
            );
        }

        return this;
    }

    public SdJwtBatchAssert haveDayRoundedExpIfPresent() {
        final long secondsInDay = 24 * 60 * 60;
        for (String sdJwt : sdJwts) {
            final SignedJWT jwt = parse(sdJwt);
            try {
                final Date exp = jwt.getJWTClaimsSet().getExpirationTime();
                if (exp == null) {
                    continue;
                }
                final long epoch = exp.toInstant().getEpochSecond();
                if (epoch % secondsInDay != secondsInDay - 1) {
                    throw new AssertionError(
                            "exp is not rounded to end of day (23:59:59 UTC). Value: " + epoch
                    );
                }
            } catch (ParseException e) {
                throw new AssertionError(e);
            }
        }
        return this;
    }
}

