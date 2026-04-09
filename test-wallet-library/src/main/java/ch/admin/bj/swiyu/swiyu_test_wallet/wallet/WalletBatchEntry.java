package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.gen.verifier.model.DcqlClaimDto;
import ch.admin.bj.swiyu.gen.verifier.model.RequestObject;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.ECCryptoSupport;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@Slf4j
@Getter
@Setter
public class WalletBatchEntry extends WalletEntry {

    private record SdJwtParts(String jwt, List<String> disclosures) {}

    private record DisclosureMatch(boolean matched, Set<String> satisfiedClaimKeys) {}

    private final List<KeyPair> holderKeyPairs = new ArrayList<>();
    private final List<ECKey> holderPublicKeys = new ArrayList<>();
    private final List<JwtProof> proofs = new ArrayList<>();
    private final List<String> issuedCredentials = new ArrayList<>();
    private final List<String> sdJwts = new ArrayList<>();

    public WalletBatchEntry(Wallet wallet) {
        super(wallet);
    }

    public String createPresentationForSdJwtIndex(final int index, RequestObject requestObject) {
        final String issuerSdJwt = issuedCredentials.get(index);
        final KeyPair keyPair = holderKeyPairs.get(index);
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("kb+jwt"))
                    .build();

            String sdJwtHash = hashSdJwt(issuerSdJwt);
            String audience = requestObject.getClientId();
            String nonce = requestObject.getNonce();

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .claim("sd_hash", sdJwtHash)
                    .audience(audience)
                    .claim("nonce", nonce)
                    .issueTime(new Date())
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            signedJWT.sign(ECCryptoSupport.createECDSASigner(keyPair.getPrivate()));

            String serializedJwt = signedJWT.serialize();
            return issuerSdJwt + serializedJwt;
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public String createSelectiveDisclosurePresentationForSdJwtIndex(
            final int index,
            final RequestObject requestObject
    ) {
        final String issuerSdJwt = issuedCredentials.get(index);
        final KeyPair keyPair = holderKeyPairs.get(index);

        try {
            final List<DcqlClaimDto> requestedClaims = extractRequestedClaims(requestObject);

            final SdJwtParts parts = splitIssuedSdJwt(issuerSdJwt);
            final JsonNode payload = extractPayload(parts.jwt());

            final Map<String, List<Object>> digestToPath = buildDigestPathMap(payload, new ArrayList<>());

            final List<String> selectedDisclosures = new ArrayList<>();
            final Set<String> satisfiedClaimIds = new HashSet<>();

            for (String disclosure : parts.disclosures()) {
                final DisclosureMatch match = matchDisclosureToRequestedClaims(
                        disclosure,
                        digestToPath,
                        requestedClaims
                );

                if (match.matched()) {
                    selectedDisclosures.add(disclosure);
                    satisfiedClaimIds.addAll(match.satisfiedClaimKeys());
                }
            }

            ensureAllRequiredClaimsSatisfied(requestedClaims, satisfiedClaimIds);

            final String filteredSdJwt = rebuildSdJwt(parts.jwt(), selectedDisclosures);

            final String kbJwt = buildKeyBindingJwt(filteredSdJwt, requestObject, keyPair);

            return filteredSdJwt + kbJwt;

        } catch (Exception e) {
            throw new IllegalStateException("Failed to create selective disclosure presentation", e);
        }
    }

    private List<DcqlClaimDto> extractRequestedClaims(RequestObject requestObject) {
        if (requestObject.getDcqlQuery() == null
                || requestObject.getDcqlQuery().getCredentials() == null
                || requestObject.getDcqlQuery().getCredentials().isEmpty()) {
            return List.of();
        }

        List<DcqlClaimDto> claims = requestObject.getDcqlQuery().getCredentials().get(0).getClaims();
        return claims == null ? List.of() : claims;
    }

    private SdJwtParts splitIssuedSdJwt(String issuerSdJwt) {
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

    private String rebuildSdJwt(String jwt, List<String> selectedDisclosures) {
        if (selectedDisclosures.isEmpty()) {
            return jwt;
        }
        return jwt + "~" + String.join("~", selectedDisclosures) + "~";
    }

    private String buildKeyBindingJwt(String filteredSdJwt, RequestObject requestObject, KeyPair keyPair)
            throws JOSEException {

        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("kb+jwt"))
                .build();

        final String sdJwtHash = hashAsciiSha256Base64Url(filteredSdJwt);

        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("sd_hash", sdJwtHash)
                .audience(requestObject.getClientId())
                .claim("nonce", requestObject.getNonce())
                .issueTime(new Date())
                .build();

        final SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(ECCryptoSupport.createECDSASigner(keyPair.getPrivate()));

        return signedJWT.serialize();
    }

    private String hashAsciiSha256Base64Url(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private JsonNode extractPayload(String jwt) {
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

    private List<Object> decodeDisclosure(String disclosure) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(disclosure);
            String json = new String(decoded, StandardCharsets.UTF_8);
            return new ObjectMapper().readValue(json, new com.fasterxml.jackson.core.type.TypeReference<List<Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException("Invalid disclosure: " + disclosure, e);
        }
    }

    private Map<String, List<Object>> buildDigestPathMap(JsonNode node, List<Object> currentPath) {
        Map<String, List<Object>> result = new HashMap<>();

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
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

    private DisclosureMatch matchDisclosureToRequestedClaims(
            String disclosure,
            Map<String, List<Object>> digestToPath,
            List<DcqlClaimDto> requestedClaims
    ) {
        String digest = hashAsciiSha256Base64Url(disclosure);
        List<Object> actualPath = resolveDisclosurePath(disclosure, digestToPath);

        if (actualPath == null) {
            return new DisclosureMatch(false, Set.of());
        }

        List<Object> decodedDisclosure = decodeDisclosure(disclosure);
        Object disclosedValue = extractDisclosedValue(decodedDisclosure);

        Set<String> satisfied = new HashSet<>();

        for (int i = 0; i < requestedClaims.size(); i++) {
            DcqlClaimDto claim = requestedClaims.get(i);
            List<Object> requestedPath = claim.getPath();

            if (requestedPath == null || requestedPath.isEmpty()) {
                continue;
            }

            boolean pathMatches = matchesRequestedPath(actualPath, requestedPath);
            if (!pathMatches) {
                continue;
            }

            boolean valueMatches = matchesRequestedValues(disclosedValue, claim.getValues());
            if (!valueMatches) {
                continue;
            }

            satisfied.add(claimKey(i, claim));
        }

        return new DisclosureMatch(!satisfied.isEmpty(), satisfied);
    }
    private Object extractDisclosedValue(List<Object> disclosureParts) {
        if (disclosureParts.size() == 3) {
            return disclosureParts.get(2);
        }
        if (disclosureParts.size() == 2) {
            return disclosureParts.get(1);
        }
        throw new IllegalStateException("Unexpected disclosure format: " + disclosureParts);
    }

    private boolean matchesRequestedPath(
            List<Object> actualPath,
            List<Object> requestedPath
    ) {
        if (actualPath == null || requestedPath == null || requestedPath.isEmpty()) {
            return false;
        }

        if (actualPath.equals(requestedPath)) {
            return true;
        }

        // Wildcard array element: ["nationalities", null]
        if (requestedPath.size() == 2
                && requestedPath.get(0) instanceof String
                && requestedPath.get(1) == null) {
            return actualPath.size() == 2
                    && Objects.equals(actualPath.get(0), requestedPath.get(0))
                    && actualPath.get(1) instanceof Integer;
        }

        return false;
    }

    private boolean matchesRequestedValues(Object disclosedValue, List<Object> requestedValues) {
        if (requestedValues == null || requestedValues.isEmpty()) {
            return true;
        }

        for (Object requestedValue : requestedValues) {
            if (Objects.equals(disclosedValue, requestedValue)) {
                return true;
            }
        }

        return false;
    }

    private void ensureAllRequiredClaimsSatisfied(
            List<DcqlClaimDto> requestedClaims,
            Set<String> satisfiedClaimIds
    ) {
        for (int i = 0; i < requestedClaims.size(); i++) {
            DcqlClaimDto claim = requestedClaims.get(i);
            String key = claimKey(i, claim);

            if (!satisfiedClaimIds.contains(key)) {
                throw new IllegalStateException(
                        "Cannot satisfy requested DCQL claim path: " + claim.getPath()
                );
            }
        }
    }

    private String claimKey(int index, DcqlClaimDto claim) {
        if (claim.getId() != null && !claim.getId().isBlank()) {
            return claim.getId();
        }
        return "claim-" + index + "-" + claim.getPath();
    }

    private List<Object> resolveDisclosurePath(
            String disclosure,
            Map<String, List<Object>> digestToPath
    ) {
        String digest = hashAsciiSha256Base64Url(disclosure);
        List<Object> parentPath = digestToPath.get(digest);

        if (parentPath == null) {
            return null;
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

    private List<String> matchArrayElements(
            final List<String> arrayElementDisclosures,
            final List<Object> requestPath,
            final List<Object> allowedValues
    ) {
        final List<String> matchedElements = new ArrayList<>();

        Integer targetIndex = null;
        boolean includeAllIndices = true;

        if (requestPath.size() == 2) {
            Object indexComponent = requestPath.get(1);
            if (indexComponent instanceof Integer) {
                targetIndex = (Integer) indexComponent;
                includeAllIndices = false;
                log.info("    Array with specific index: {}", targetIndex);
            } else if (indexComponent == null) {
                includeAllIndices = true;
                log.info("    Array with wildcard index (null): all elements");
            }
        } else {
            includeAllIndices = true;
            log.info("    Array without index specification: all elements");
        }

        int elementIndex = 0;
        for (String disclosure : arrayElementDisclosures) {
            try {
                String decoded = new String(Base64.getUrlDecoder().decode(disclosure), StandardCharsets.UTF_8);
                ObjectMapper mapper = new ObjectMapper();
                List<?> parts_list = mapper.readValue(decoded, List.class);

                if (parts_list.size() == 2) {
                    Object arrayValue = parts_list.get(1);

                    boolean indexMatches = includeAllIndices || (targetIndex != null && elementIndex == targetIndex);

                    if (indexMatches) {
                        if (allowedValues == null || allowedValues.isEmpty()) {
                            matchedElements.add(disclosure);
                            log.debug("      Element [{}] matched (no value filter): {}", elementIndex, arrayValue);
                        } else {
                            if (allowedValues.contains(arrayValue)) {
                                matchedElements.add(disclosure);
                                log.debug("      Element [{}] matched (value filter): {} in {}", elementIndex, arrayValue, allowedValues);
                            } else {
                                log.debug("      Element [{}] filtered out: {} not in {}", elementIndex, arrayValue, allowedValues);
                            }
                        }
                    } else {
                        log.debug("      Element [{}] skipped (index doesn't match): target={}", elementIndex, targetIndex);
                    }

                    elementIndex++;
                }
            } catch (Exception e) {
                log.debug("    Error processing disclosure for array matching: {}", e.getMessage());
            }
        }

        return matchedElements;
    }


    private String computeDisclosureDigest(String disclosure) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(disclosure.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }


    private String hashSdJwt(String sdJwt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(sdJwt.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public void generateHolderKeys() {
        final int count = getIssuerMetadata().getBatchCredentialIssuance().getBatchSize();
        generateHolderKeys(count);
    }

    public void generateHolderKeys(int count) {
        holderKeyPairs.clear();
        holderPublicKeys.clear();

        for (int i = 0; i < count; i++) {
            var pair = ECCryptoSupport.generateECKeyPair();
            var ec = new ECKey.Builder(Curve.P_256, (java.security.interfaces.ECPublicKey) pair.getPublic())
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID("holder-key-" + UUID.randomUUID())
                    .build();
            holderKeyPairs.add(pair);
            holderPublicKeys.add(ec);
        }
    }

    public void createProofs() {
        if (getCredentialOffer() == null) {
            throw new IllegalStateException("Offer or token missing for proof generation");
        }

        proofs.clear();

        for (ECKey pub : holderPublicKeys) {
            final JwtProof proof = new JwtProof(
                    getIssuerMetadata().getCredentialIssuer(),
                    getCNonce(),
                    pub,
                    holderKeyPairs.get(holderPublicKeys.indexOf(pub))
            );
            proofs.add(proof);
        }
    }

    public void createProofs(final String uniqueNonce) {
        if (getCredentialOffer() == null) {
            throw new IllegalStateException("Offer or token missing for proof generation");
        }
        proofs.clear();
        for (ECKey pub : holderPublicKeys) {
            var proof = new JwtProof(
                    getIssuerMetadata().getCredentialIssuer(),
                    uniqueNonce,
                    pub,
                    holderKeyPairs.get(holderPublicKeys.indexOf(pub))
            );
            proofs.add(proof);
        }
    }

    public List<String> getProofsAsJwt() {
        return proofs.stream().map(JwtProof::toJwt).toList();
    }

    public void setProofsFromJwt(final List<JwtProof> proofs) {
        this.proofs.clear();
        for (JwtProof p : proofs) {
            this.proofs.add(p);
        }
    }

    public void clearIssuedCredentials() {
        issuedCredentials.clear();
    }

    public void addIssuedCredential(String jwt) {
        issuedCredentials.add(jwt);
    }

    public String getVerifiableCredential(final int index) {
        if (issuedCredentials.size() <= index) {
            throw new IndexOutOfBoundsException("index out of bounds for verifiable credential " + index);
        }

        return issuedCredentials.get(index);
    }

    public List<String> getIssuedCredentials() {
        return Collections.unmodifiableList(issuedCredentials);
    }
    
    public WalletBatchEntry duplicate() {
        WalletBatchEntry copy = new WalletBatchEntry(this.getWallet());

        copy.setIssuerVCDeepLink(this.getIssuerVCDeepLink());
        copy.setCredentialOffer(this.getCredentialOffer());
        copy.setIssuerWellKnownConfiguration(this.getIssuerWellKnownConfiguration());
        copy.setIssuerMetadata(this.getIssuerMetadata());
        copy.setToken(this.getToken());
        copy.setCNonce(this.getCNonce());
        copy.setIssuerSdJwt(this.getIssuerSdJwt());
        copy.setTransactionId(this.getTransactionId());

        return copy;
    }

    public void setHolderPublicKeys(final List<ECKey> initialHolderPublicKeys) {
        this.holderPublicKeys.clear();
        for (final ECKey pub : initialHolderPublicKeys) {
            this.holderPublicKeys.add(pub);
        }
    }

    public void setHolderKeyPairs(final List<KeyPair> initialHolderKeyPairs) {
        this.holderKeyPairs.clear();
        for (final KeyPair pair : initialHolderKeyPairs) {
            this.holderKeyPairs.add(pair);
        }
    }

    /**
     * Matches nested object fields for a given DCQL path.
     *
     * Handles DCQL path patterns for nested objects:
     * - ["address", "street_address"] → The street_address field of address object
     * - ["address", "locality"] → The locality field of address object
     * - ["person", "address", "postal_code"] → Deep nesting
     *
     * For nested objects, the disclosure key should be the leaf field name.
     * We match it by checking if the full path hierarchy exists in disclosures.
     *
     * @param disclosures all disclosure strings
     * @param requestPath the full DCQL path (e.g., ["address", "street_address"])
     * @param allowedValues optional list of values to filter by (null = all values)
     * @return list of matching disclosure strings
     */
    private List<String> matchNestedObjectFields(
            final List<String> disclosures,
            final List<Object> requestPath,
            final List<Object> allowedValues
    ) {
        final List<String> matchedFields = new ArrayList<>();

        // The leaf field is the last component in the path
        String leafField = (String) requestPath.get(requestPath.size() - 1);
        log.info("    Nested object path: {}, looking for field: '{}'", requestPath, leafField);

        for (String disclosure : disclosures) {
            try {
                String decoded = new String(Base64.getUrlDecoder().decode(disclosure), StandardCharsets.UTF_8);
                ObjectMapper mapper = new ObjectMapper();
                List<?> parts_list = mapper.readValue(decoded, List.class);

                // Nested object fields have 3 parts: [salt, key, value]
                if (parts_list.size() == 3) {
                    Object keyComponent = parts_list.get(1);
                    Object valueComponent = parts_list.get(2);

                    // Check if this is the field we're looking for
                    if (keyComponent instanceof String && leafField.equals(keyComponent)) {
                        // Check value filter if present
                        if (allowedValues == null || allowedValues.isEmpty()) {
                            matchedFields.add(disclosure);
                            log.debug("      Field '{}' matched (no value filter): {}", leafField, valueComponent);
                        } else {
                            // Apply value filter
                            if (allowedValues.contains(valueComponent)) {
                                matchedFields.add(disclosure);
                                log.debug("      Field '{}' matched (value filter): {} in {}", leafField, valueComponent, allowedValues);
                            } else {
                                log.debug("      Field '{}' filtered out: {} not in {}", leafField, valueComponent, allowedValues);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                log.debug("    Error processing disclosure for nested object matching: {}", e.getMessage());
            }
        }

        return matchedFields;
    }
}
