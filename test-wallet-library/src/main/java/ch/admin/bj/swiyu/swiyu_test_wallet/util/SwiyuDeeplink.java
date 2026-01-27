package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.ToString;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

@Getter
@ToString
public class SwiyuDeeplink {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String rawDeeplink;
    private final JsonNode data;

    public SwiyuDeeplink(final String deeplink) {
        this.rawDeeplink = deeplink;
        this.data = parseCredentialOffer(deeplink);
    }

    public String getCredentialIssuer() {
        return getText("credential_issuer");
    }

    public String getCredentialIssuerTenantId() {
        final String completeCredentialIssuer = getText("credential_issuer");
        if (completeCredentialIssuer != null && completeCredentialIssuer.contains("/")) {
            return completeCredentialIssuer.substring(completeCredentialIssuer.lastIndexOf("/") + 1);
        }
        return null;
    }

    public boolean hasTenantId() {
        return getCredentialIssuerTenantId() != null;
    }

    public String getVersion() {
        return getText("version");
    }

    public List<String> getCredentialConfigurationIds() {
        final JsonNode ids = data.get("credential_configuration_ids");
        if (ids == null || !ids.isArray()) {
            return List.of();
        }

        final List<String> result = new ArrayList<>();
        final Iterator<JsonNode> it = ids.elements();
        while (it.hasNext()) {
            result.add(it.next().asText());
        }
        return result;
    }

    public String getPreAuthorizedCode() {
        final JsonNode grants = data.get("grants");
        if (grants == null) {
            return null;
        }

        final JsonNode grant =
                grants.get("urn:ietf:params:oauth:grant-type:pre-authorized_code");

        if (grant == null) {
            return null;
        }

        final JsonNode code = grant.get("pre-authorized_code");
        return code != null ? code.asText() : null;
    }

    public boolean isPreAuthorizedFlow() {
        return getPreAuthorizedCode() != null;
    }

    public JsonNode getRawData() {
        return data;
    }

    private static JsonNode parseCredentialOffer(final String deeplink) {
        try {
            final URI uri = URI.create(deeplink);
            final String encoded = extractQueryParam(uri, "credential_offer");

            final String decoded =
                    URLDecoder.decode(encoded, StandardCharsets.UTF_8);

            return MAPPER.readTree(decoded);

        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid Swiyu deeplink", e);
        }
    }

    private static String extractQueryParam(final URI uri, final String name) {
        final String query = uri.getQuery();
        if (query == null) {
            throw new IllegalArgumentException("No query parameters in deeplink");
        }

        return Arrays.stream(query.split("&"))
                .filter(p -> p.startsWith(name + "="))
                .map(p -> p.substring(name.length() + 1))
                .findFirst()
                .orElseThrow(() ->
                        new IllegalArgumentException("Missing parameter: " + name));
    }

    private String getText(final String key) {
        final JsonNode node = data.get(key);
        return node != null ? node.asText() : null;
    }
}
