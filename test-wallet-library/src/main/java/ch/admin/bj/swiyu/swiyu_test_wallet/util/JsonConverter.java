package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.experimental.UtilityClass;

import java.util.ArrayList;
import java.util.List;

import static com.fasterxml.jackson.databind.DeserializationFeature.READ_ENUMS_USING_TO_STRING;
import static com.fasterxml.jackson.databind.SerializationFeature.WRITE_ENUMS_USING_TO_STRING;

/**
 * Converts json strings to typed objects and vice versa using jackson.
 */
@UtilityClass
public class JsonConverter {

    private static final ObjectMapper DEFAULT_OBJECT_MAPPER = createObjectMapper();

    private static ObjectMapper createObjectMapper() {
        var objectMapper = new ObjectMapper();
        objectMapper.enable(WRITE_ENUMS_USING_TO_STRING);
        objectMapper.enable(READ_ENUMS_USING_TO_STRING);
        objectMapper.findAndRegisterModules();
        return objectMapper;
    }

    public static <T> T toObject(String json, Class<T> responseType) {
        try {
            return DEFAULT_OBJECT_MAPPER.readValue(json, responseType);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    public static JsonNode toJsonNode(final String json) {
        try {
            return DEFAULT_OBJECT_MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    public static ObjectNode toObjectNode(String json) {
        var jsonNode = toJsonNode(json);
        if (jsonNode.isObject())
            return (ObjectNode) jsonNode;
        throw new IllegalStateException("Cannot convert [" + json + "] into object node.");
    }

    public static ArrayNode toArrayNode(List<String> items) {
        var array = DEFAULT_OBJECT_MAPPER.createArrayNode();
        items.forEach(array::add);
        return array;
    }

    public static String toJsonString(Object pojo) {
        var writer = DEFAULT_OBJECT_MAPPER.writer().withDefaultPrettyPrinter();
        try {
            return writer.writeValueAsString(pojo);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    public static ObjectMapper objectMapper() {
        return DEFAULT_OBJECT_MAPPER;
    }

    public List<String> toStringList(JsonNode array) {
        if (!array.isArray()) {
            throw new IllegalArgumentException("Node is not an array");
        }
        List<String> list = new ArrayList<>();
        for (int i = 0; i < array.size(); i++) {
            String value = array.get(i).asText();
            list.add(value);
        }
        return list;
    }

    public static String escapeJson(String input) {
        if (input == null) {
            return null;
        }

        StringBuilder escaped = new StringBuilder();

        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);

            switch (ch) {
                case '"':
                    escaped.append("\\\"");
                    break;
                case '\\':
                    escaped.append("\\\\");
                    break;
                case '\b':
                    escaped.append("\\b");
                    break;
                case '\f':
                    escaped.append("\\f");
                    break;
                case '\n':
                    escaped.append("\\n");
                    break;
                case '\r':
                    escaped.append("\\r");
                    break;
                case '\t':
                    escaped.append("\\t");
                    break;
                default:
                    // If the character is a control character or non-printable, use Unicode escape
                    if (ch < 0x20 || ch > 0x7e) {
                        escaped.append(String.format("\\u%04x", (int) ch));
                    } else {
                        escaped.append(ch);
                    }
                    break;
            }
        }

        return escaped.toString();
    }
}
