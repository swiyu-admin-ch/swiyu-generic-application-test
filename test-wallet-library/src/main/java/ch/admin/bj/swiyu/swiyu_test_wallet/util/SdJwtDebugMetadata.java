package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Getter;
import lombok.ToString;
import org.assertj.core.data.MapEntry;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Getter
@ToString
public class SdJwtDebugMetadata {

    private final String rawSdJwt;
    private final JsonNode issuerPayload;
    private final JsonNode issuerHeader;
    private final List<JsonNode> disclosures;

    public SdJwtDebugMetadata(final String sdJwt) {
        this.rawSdJwt = sdJwt;
        this.issuerHeader = SdJwtSupport.extractHeader(sdJwt);
        this.issuerPayload = SdJwtSupport.extractPayload(sdJwt);
        this.disclosures = SdJwtSupport.extractDisclosuresAsJson(sdJwt);
    }

    public String getIssuer() {
        return issuerPayload.path("iss").asText(null);
    }

    public boolean hasKeyBinding() {
        return issuerPayload.has("cnf");
    }

    public List<String> getSdClaimDigests() {
        JsonNode sd = issuerPayload.get("_sd");
        if (sd == null || !sd.isArray()) {
            return List.of();
        }
        return sd.findValuesAsText("");
    }

    public Map<String, String> getRevealedClaims() {
        Map<String, String> result = new HashMap<>();
        for (JsonNode disclosure : disclosures) {
            result.put(
                    disclosure.get(1).asText(),
                    disclosure.get(2).asText()
            );
        }
        return result;
    }

    public String getClaimValue(String claimKey) {
        for (JsonNode disclosure : disclosures) {
            if (disclosure.get(1).asText().equals(claimKey)) {
                return disclosure.get(2).asText();
            }
        }
        return null;
    }

    public boolean isClaimValid(MapEntry<String, Object> claimEntry) {
        final String value = getClaimValue(claimEntry.getKey());
        return value != null && value.equals(claimEntry.getValue().toString());
    }
}
