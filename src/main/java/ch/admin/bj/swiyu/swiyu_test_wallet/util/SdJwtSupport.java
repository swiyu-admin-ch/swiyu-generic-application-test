package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.experimental.UtilityClass;

import java.util.*;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.JsonConverter.toJsonNode;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.JwtSupport.decodeHeaderAsJsonNode;
import static ch.admin.bj.swiyu.swiyu_test_wallet.util.JwtSupport.decodePayloadToJsonNode;

@UtilityClass
public class SdJwtSupport {

    public static JsonNode extractHeader(String sdjwt) {
        return decodeHeaderAsJsonNode(extractJwt(sdjwt));
    }

    public static JsonNode extractPayload(String sdjwt) {
        return decodePayloadToJsonNode(extractJwt(sdjwt));
    }

    public List<JsonNode> extractDisclosuresAsJson(String sdjwt) {
        List<JsonNode> disclosures = new ArrayList<>();

        var sdjwtParts = sdjwt.split("~");
        var encodedDisclosures = Arrays.copyOfRange(sdjwtParts, 1, sdjwtParts.length);
        for (var encodedDisclosure : encodedDisclosures) {
            String disclosureAsStr = new String(Base64.getDecoder().decode(encodedDisclosure));
            var disclosure = toJsonNode(disclosureAsStr);
            disclosures.add(disclosure);
        }
        return disclosures;
    }

    public Map<String, String> extractDisclosures(String sdjwt) {
        List<JsonNode> jsonNodes = extractDisclosuresAsJson(sdjwt);
        Map<String, String> disclosures = new HashMap<>();
        for (JsonNode jsonNode : jsonNodes) {
            String key = jsonNode.get(1).asText();
            String value = jsonNode.get(2).asText();
            disclosures.put(key, value);
        }
        return disclosures;
    }

    public static String extractJwt(String sdjwt) {
        return sdjwt.split("~")[0];
    }

    public static List<String> getSortedDisclosureKeys(List<JsonNode> disclosures) {
        return disclosures.stream()
                .map(disclosure -> disclosure.get(1).asText())  // get key
                .sorted()
                .toList();
    }
}
