package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.credential;

import ch.admin.bj.swiyu.gen.verifier.model.DcqlClaimDto;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto.Sha256Base64Url;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Chooses the Disclosures a Wallet presents for a DCQL query: the ones needed to reveal the requested claims, and no other
 * (OID4VP 1.0 §6.3 and §7 Claims Path Pointer, §15.4.2 only the strictly necessary claims; RFC 9901 §4.2 Disclosures).
 *
 * <p>Pure: it only reads the SD-JWT and the claim paths. A path element that is a string selects an object property, an
 * integer selects one array element, and {@code null} selects every array element.
 */
public final class DisclosureSelector {

    private static final int ARRAY_DISCLOSURE_PART_COUNT = 2;
    private static final int OBJECT_DISCLOSURE_PART_COUNT = 3;
    private static final int ARRAY_ELEMENT_PATH_LENGTH = 2;
    private static final int ARRAY_PROPERTY_PATH_LENGTH = 3;

    private DisclosureSelector() {
    }

    private record SdJwtParts(String jwt, List<String> disclosures) {}

    /**
     * @param issuerSdJwt     the credential, {@code <Issuer-signed JWT>~<D1>~...~<DN>~}
     * @param requestedClaims the Claims Queries of the Credential Query (their {@code path})
     * @return {@code <Issuer-signed JWT>~<selected Disclosures>~}, ready for a Key Binding JWT to be appended
     */
    public static String select(final String issuerSdJwt, final List<DcqlClaimDto> requestedClaims) {
        final SdJwtParts parts = splitIssuedSdJwt(issuerSdJwt);
        final JsonNode payload = extractPayload(parts.jwt());

        final Map<String, List<Object>> digestToPath = buildDigestPathMap(payload, new ArrayList<>());
        augmentDigestMapFromDisclosures(parts.disclosures(), digestToPath);

        final List<String> selectedDisclosures = new ArrayList<>();
        for (String disclosure : parts.disclosures()) {
            if (matchesAnyRequestedPath(disclosure, digestToPath, requestedClaims)) {
                selectedDisclosures.add(disclosure);
            }
        }
        return rebuildSdJwt(parts.jwt(), selectedDisclosures);
    }


    private static SdJwtParts splitIssuedSdJwt(String issuerSdJwt) {
        String[] parts = issuerSdJwt.split("~", -1);

        if (parts.length == 0) {
            throw new IllegalStateException("Invalid SD-JWT");
        }

        String jwt = parts[0];
        List<String> disclosures = new ArrayList<>();

        for (int i = 1; i < parts.length; i++) {
            if (parts[i] != null && !parts[i].isBlank()) {
                disclosures.add(parts[i]);
            }
        }

        return new SdJwtParts(jwt, disclosures);
    }

    /**
     * RFC 9901 §4.3.1: {@code <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~}. Every part, including the
     * Issuer-signed JWT when no Disclosure is selected, is followed by a tilde, so that the Key Binding JWT appended
     * afterwards is a separate part and {@code sd_hash} covers the text up to and including the last tilde.
     */
    private static String rebuildSdJwt(String jwt, List<String> selectedDisclosures) {
        if (selectedDisclosures.isEmpty()) {
            return jwt + "~";
        }
        return jwt + "~" + String.join("~", selectedDisclosures) + "~";
    }

    private static JsonNode extractPayload(String jwt) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(jwtPayloadPart(jwt));
            return new ObjectMapper().readTree(decoded);
        } catch (JacksonException | IllegalArgumentException | IllegalStateException e) {
            throw new IllegalStateException("Unable to parse JWT payload", e);
        }
    }

    private static String jwtPayloadPart(final String jwt) {
        final String[] parts = jwt.split("\\.");
        if (parts.length < ARRAY_DISCLOSURE_PART_COUNT) {
            throw new IllegalStateException("Invalid JWT");
        }
        return parts[1];
    }

    private static List<Object> decodeDisclosure(String disclosure) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(disclosure);
            String json = new String(decoded, StandardCharsets.UTF_8);
            return new ObjectMapper().readValue(json, new tools.jackson.core.type.TypeReference<List<Object>>() {});
        } catch (JacksonException | IllegalArgumentException e) {
            throw new IllegalStateException("Invalid disclosure: " + disclosure, e);
        }
    }

    private static Map<String, List<Object>> buildDigestPathMap(JsonNode node, List<Object> currentPath) {
        final Map<String, List<Object>> result = new HashMap<>();
        if (node.isObject()) {
            indexObjectDigests(node, currentPath, result);
        } else if (node.isArray()) {
            indexArrayDigests(node, currentPath, result);
        }
        return result;
    }

    // Every stored digest keeps an independent snapshot of its parent path.
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    private static void indexObjectDigests(
            final JsonNode node, final List<Object> currentPath, final Map<String, List<Object>> result) {
        for (Map.Entry<String, JsonNode> entry : node.properties()) {
            final String key = entry.getKey();
            final JsonNode value = entry.getValue();
            if ("_sd".equals(key) && value.isArray()) {
                for (JsonNode digestNode : value) {
                    result.put(digestNode.asText(), new ArrayList<>(currentPath));
                }
            } else {
                result.putAll(buildDigestPathMap(value, appendPath(currentPath, key)));
            }
        }
    }

    private static void indexArrayDigests(
            final JsonNode node, final List<Object> currentPath, final Map<String, List<Object>> result) {
        for (int i = 0; i < node.size(); i++) {
            final JsonNode element = node.get(i);
            final List<Object> elementPath = appendPath(currentPath, i);
            if (element.isObject() && element.size() == 1 && element.has("...")) {
                result.put(element.get("...").asText(), elementPath);
            } else {
                result.putAll(buildDigestPathMap(element, elementPath));
            }
        }
    }

    private static List<Object> appendPath(final List<Object> parentPath, final Object segment) {
        final List<Object> path = new ArrayList<>(parentPath);
        path.add(segment);
        return path;
    }

    private static void augmentDigestMapFromDisclosures(List<String> disclosures, Map<String, List<Object>> digestToPath) {
        boolean changed = true;
        while (changed) {
            changed = false;
            for (String disclosure : disclosures) {
                changed |= augmentDisclosure(disclosure, digestToPath);
            }
        }
    }

    private static boolean augmentDisclosure(final String disclosure, final Map<String, List<Object>> digestToPath) {
        final List<Object> parts = decodeDisclosure(disclosure);
        if (parts.size() != ARRAY_DISCLOSURE_PART_COUNT && parts.size() != OBJECT_DISCLOSURE_PART_COUNT) {
            return false;
        }
        final List<Object> parentPath = digestToPath.get(Sha256Base64Url.ofUsAscii(disclosure));
        if (parentPath == null) {
            return false;
        }

        final List<Object> valuePath = new ArrayList<>(parentPath);
        final Object value;
        if (parts.size() == OBJECT_DISCLOSURE_PART_COUNT) {
            final Object key = parts.get(1);
            if (!(key instanceof String)) {
                return false;
            }
            valuePath.add(key);
            value = parts.get(2);
        } else {
            value = parts.get(1);
        }
        if (value instanceof Map<?, ?> valueMap) {
            return registerObjectDigests(valueMap, valuePath, digestToPath);
        }
        return value instanceof List<?> arrayValue && registerArrayDigests(arrayValue, valuePath, digestToPath);
    }

    // Each nested digest retains its own path while later Disclosures extend sibling paths.
    @SuppressWarnings({"unchecked", "PMD.AvoidInstantiatingObjectsInLoops"})
    private static boolean registerObjectDigests(
            final Map<?, ?> value, final List<Object> valuePath, final Map<String, List<Object>> digestToPath) {
        final Object sdNode = value.get("_sd");
        if (!(sdNode instanceof List<?>)) {
            return false;
        }
        boolean changed = false;
        for (String nestedDigest : (List<String>) sdNode) {
            if (!digestToPath.containsKey(nestedDigest)) {
                digestToPath.put(nestedDigest, new ArrayList<>(valuePath));
                changed = true;
            }
        }
        return changed;
    }

    private static boolean registerArrayDigests(
            final List<?> value, final List<Object> valuePath, final Map<String, List<Object>> digestToPath) {
        boolean changed = false;
        for (int i = 0; i < value.size(); i++) {
            if (value.get(i) instanceof Map<?, ?> element) {
                final Object digest = element.get("...");
                if (digest instanceof String stringDigest && !digestToPath.containsKey(stringDigest)) {
                    digestToPath.put(stringDigest, appendPath(valuePath, i));
                    changed = true;
                }
            }
        }
        return changed;
    }

    private static boolean matchesAnyRequestedPath(
            String disclosure,
            Map<String, List<Object>> digestToPath,
            List<DcqlClaimDto> requestedClaims
    ) {
        final List<Object> actualPath = resolveDisclosurePath(disclosure, digestToPath);
        return !actualPath.isEmpty() && requestedClaims.stream()
                .map(DcqlClaimDto::getPath)
                .anyMatch(requestedPath -> requestedPath != null
                        && !requestedPath.isEmpty()
                        && matchesRequestedPath(actualPath, requestedPath));
    }

    private static boolean matchesRequestedPath(List<Object> actualPath, List<Object> requestedPath) {
        if (isEmptyPath(actualPath) || isEmptyPath(requestedPath)) {
            return false;
        }
        if (actualPath.equals(requestedPath)) {
            return true;
        }
        return (actualPath.size() < requestedPath.size()
                && requestedPath.subList(0, actualPath.size()).equals(actualPath))
                || matchesArrayPath(actualPath, requestedPath);
    }

    private static boolean isEmptyPath(final List<Object> path) {
        return path == null || path.isEmpty();
    }

    private static boolean matchesArrayPath(final List<Object> actual, final List<Object> requested) {
        if (!(requested.getFirst() instanceof String)) {
            return false;
        }
        if (requested.size() == ARRAY_ELEMENT_PATH_LENGTH && requested.get(1) == null) {
            return matchesArrayElement(actual, requested);
        }
        if (requested.size() != ARRAY_PROPERTY_PATH_LENGTH || !(requested.get(2) instanceof String)) {
            return false;
        }
        if (requested.get(1) == null) {
            return matchesArrayElement(actual, requested)
                    || (matchesArrayProperty(actual, requested) && actual.get(1) instanceof Integer);
        }
        return requested.get(1) instanceof Integer && matchesIndexedArrayPath(actual, requested);
    }

    private static boolean matchesArrayElement(final List<Object> actual, final List<Object> requested) {
        return actual.size() == ARRAY_ELEMENT_PATH_LENGTH
                && Objects.equals(actual.getFirst(), requested.getFirst())
                && actual.get(1) instanceof Integer;
    }

    private static boolean matchesArrayProperty(final List<Object> actual, final List<Object> requested) {
        return actual.size() == ARRAY_PROPERTY_PATH_LENGTH
                && Objects.equals(actual.getFirst(), requested.getFirst())
                && Objects.equals(actual.get(2), requested.get(2));
    }

    private static boolean matchesIndexedArrayPath(final List<Object> actual, final List<Object> requested) {
        return (actual.size() == ARRAY_ELEMENT_PATH_LENGTH || matchesArrayProperty(actual, requested))
                && Objects.equals(actual.getFirst(), requested.getFirst())
                && Objects.equals(actual.get(1), requested.get(1));
    }

    private static List<Object> resolveDisclosurePath(
            String disclosure,
            Map<String, List<Object>> digestToPath
    ) {
        String digest = Sha256Base64Url.ofUsAscii(disclosure);
        List<Object> parentPath = digestToPath.get(digest);

        if (parentPath == null) {
            return List.of();
        }

        List<Object> parts = decodeDisclosure(disclosure);

        // Object property disclosure: [salt, key, value]
        if (parts.size() == OBJECT_DISCLOSURE_PART_COUNT) {
            Object key = parts.get(1);
            if (!(key instanceof String)) {
                throw new IllegalStateException("Invalid object disclosure key: " + key);
            }

            List<Object> fullPath = new ArrayList<>(parentPath);
            fullPath.add(key);
            return fullPath;
        }

        // Array element disclosure: [salt, value]
        if (parts.size() == ARRAY_DISCLOSURE_PART_COUNT) {
            return parentPath;
        }

        throw new IllegalStateException("Unexpected disclosure format: " + parts);
    }
}
