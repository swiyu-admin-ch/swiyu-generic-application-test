package ch.admin.bj.swiyu.swiyu_test_wallet.wallet.credential;

import ch.admin.bj.swiyu.gen.verifier.model.DcqlClaimDto;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.crypto.Sha256Base64Url;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Chooses the Disclosures a Wallet presents for a DCQL query: the ones needed to reveal the requested claims, and no other
 * (OID4VP 1.0 §6.3 and §7 Claims Path Pointer, §15.4.2 only the strictly necessary claims; RFC 9901 §4.2 Disclosures).
 *
 * <p>Pure: it only reads the SD-JWT and the claim paths. A path element that is a string selects an object property, an
 * integer selects one array element, and {@code null} selects every array element.
 */
public final class DisclosureSelector {

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
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) {
                throw new IllegalStateException("Invalid JWT");
            }

            byte[] decoded = Base64.getUrlDecoder().decode(parts[1]);
            return new ObjectMapper().readTree(decoded);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to parse JWT payload", e);
        }
    }

    private static List<Object> decodeDisclosure(String disclosure) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(disclosure);
            String json = new String(decoded, StandardCharsets.UTF_8);
            return new ObjectMapper().readValue(json, new tools.jackson.core.type.TypeReference<List<Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException("Invalid disclosure: " + disclosure, e);
        }
    }

    private static Map<String, List<Object>> buildDigestPathMap(JsonNode node, List<Object> currentPath) {
        Map<String, List<Object>> result = new HashMap<>();

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.properties().iterator();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String key = entry.getKey();
                JsonNode value = entry.getValue();

                if ("_sd".equals(key) && value.isArray()) {
                    for (JsonNode digestNode : value) {
                        result.put(digestNode.asText(), new ArrayList<>(currentPath));
                    }
                } else {
                    List<Object> childPath = new ArrayList<>(currentPath);
                    childPath.add(key);
                    result.putAll(buildDigestPathMap(value, childPath));
                }
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                JsonNode element = node.get(i);

                if (element.isObject()
                        && element.size() == 1
                        && element.has("...")) {
                    List<Object> elementPath = new ArrayList<>(currentPath);
                    elementPath.add(i);
                    result.put(element.get("...").asText(), elementPath);
                } else {
                    List<Object> childPath = new ArrayList<>(currentPath);
                    childPath.add(i);
                    result.putAll(buildDigestPathMap(element, childPath));
                }
            }
        }

        return result;
    }

    private static void augmentDigestMapFromDisclosures(List<String> disclosures, Map<String, List<Object>> digestToPath) {
        boolean changed = true;
        while (changed) {
            changed = false;
            for (String disclosure : disclosures) {
                final List<Object> decodedParts = decodeDisclosure(disclosure);
                if (decodedParts.size() != 2 && decodedParts.size() != 3) {
                    continue;
                }

                final String digest = Sha256Base64Url.ofUsAscii(disclosure);
                final List<Object> parentPath = digestToPath.get(digest);
                if (parentPath == null) {
                    continue;
                }

                final List<Object> valuePath = new ArrayList<>(parentPath);
                final Object value;
                if (decodedParts.size() == 3) {
                    final Object key = decodedParts.get(1);
                    if (!(key instanceof String)) {
                        continue;
                    }
                    valuePath.add(key);
                    value = decodedParts.get(2);
                } else if (decodedParts.size() == 2) {
                    value = decodedParts.get(1);
                } else {
                    continue;
                }

                // Case 1: value is an object with _sd — nested disclosed object fields (e.g. address)
                if (value instanceof Map) {
                    @SuppressWarnings("unchecked")
                    final Map<String, Object> valueMap = (Map<String, Object>) value;
                    final Object sdNode = valueMap.get("_sd");
                    if (sdNode instanceof List) {
                        @SuppressWarnings("unchecked")
                        final List<String> nestedDigests = (List<String>) sdNode;
                        for (final String nestedDigest : nestedDigests) {
                            if (!digestToPath.containsKey(nestedDigest)) {
                                digestToPath.put(nestedDigest, new ArrayList<>(valuePath));
                                changed = true;
                            }
                        }
                    }
                }

                // Case 2: value is an array with {"...": digest} wrappers — disclosed array elements (e.g. nationalities, degrees)
                if (value instanceof List) {
                    @SuppressWarnings("unchecked")
                    final List<Object> arrayValue = (List<Object>) value;
                    for (int i = 0; i < arrayValue.size(); i++) {
                        final Object element = arrayValue.get(i);
                        if (element instanceof Map) {
                            @SuppressWarnings("unchecked")
                            final Map<String, Object> elementMap = (Map<String, Object>) element;
                            final Object elementDigest = elementMap.get("...");
                            if (elementDigest instanceof String) {
                                if (!digestToPath.containsKey((String) elementDigest)) {
                                    final List<Object> elementPath = new ArrayList<>(valuePath);
                                    elementPath.add(i);
                                    digestToPath.put((String) elementDigest, elementPath);
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private static boolean matchesAnyRequestedPath(
            String disclosure,
            Map<String, List<Object>> digestToPath,
            List<DcqlClaimDto> requestedClaims
    ) {
        final List<Object> actualPath = resolveDisclosurePath(disclosure, digestToPath);
        if (actualPath.isEmpty()) {
            return false;
        }

        return requestedClaims.stream()
                .map(DcqlClaimDto::getPath)
                .anyMatch(requestedPath -> requestedPath != null
                        && !requestedPath.isEmpty()
                        && matchesRequestedPath(actualPath, requestedPath));
    }

    private static boolean matchesRequestedPath(
            List<Object> actualPath,
            List<Object> requestedPath
    ) {
        if (actualPath == null || actualPath.isEmpty() || requestedPath == null || requestedPath.isEmpty()) {
            return false;
        }

        if (actualPath.equals(requestedPath)) {
            return true;
        }

        if (actualPath.size() < requestedPath.size()
                && requestedPath.subList(0, actualPath.size()).equals(actualPath)) {
            return true;
        }

        if (requestedPath.size() == 2
                && requestedPath.get(0) instanceof String
                && requestedPath.get(1) == null) {
            return actualPath.size() == 2
                    && Objects.equals(actualPath.get(0), requestedPath.get(0))
                    && actualPath.get(1) instanceof Integer;
        }

        if (requestedPath.size() == 3
                && requestedPath.get(0) instanceof String
                && requestedPath.get(1) == null
                && requestedPath.get(2) instanceof String) {
            return (actualPath.size() == 2
                    && Objects.equals(actualPath.get(0), requestedPath.get(0))
                    && actualPath.get(1) instanceof Integer)
                    || (actualPath.size() == 3
                    && Objects.equals(actualPath.get(0), requestedPath.get(0))
                    && actualPath.get(1) instanceof Integer
                    && Objects.equals(actualPath.get(2), requestedPath.get(2)));
        }

        if (requestedPath.size() == 3
                && requestedPath.get(0) instanceof String
                && requestedPath.get(1) instanceof Integer
                && requestedPath.get(2) instanceof String) {
            return (actualPath.size() == 2
                    && Objects.equals(actualPath.get(0), requestedPath.get(0))
                    && Objects.equals(actualPath.get(1), requestedPath.get(1)))
                    || (actualPath.size() == 3
                    && Objects.equals(actualPath.get(0), requestedPath.get(0))
                    && Objects.equals(actualPath.get(1), requestedPath.get(1))
                    && Objects.equals(actualPath.get(2), requestedPath.get(2)));
        }

        return false;
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
        if (parts.size() == 3) {
            Object key = parts.get(1);
            if (!(key instanceof String)) {
                throw new IllegalStateException("Invalid object disclosure key: " + key);
            }

            List<Object> fullPath = new ArrayList<>(parentPath);
            fullPath.add(key);
            return fullPath;
        }

        // Array element disclosure: [salt, value]
        if (parts.size() == 2) {
            return parentPath;
        }

        throw new IllegalStateException("Unexpected disclosure format: " + parts);
    }
}
