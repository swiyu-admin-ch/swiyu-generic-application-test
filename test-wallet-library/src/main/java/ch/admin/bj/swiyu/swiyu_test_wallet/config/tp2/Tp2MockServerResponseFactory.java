package ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2;

import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.TestSupportException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.protocol.HTTP;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.HttpStatusCode;

import java.util.List;
import java.util.Map;

import static org.mockserver.model.HttpResponse.response;

final class Tp2MockServerResponseFactory {

    private final ObjectMapper objectMapper;

    Tp2MockServerResponseFactory(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    HttpResponse jsonResponse(Object body) {
        try {
            return response()
                    .withStatusCode(HttpStatusCode.OK_200.code())
                    .withHeader(HTTP.CONTENT_TYPE, "application/json")
                    .withBody(objectMapper.writeValueAsString(body));
        } catch (JsonProcessingException e) {
            throw new TestSupportException("Cannot serialize MockServer response: " + e.getMessage());
        }
    }

    HttpResponse jwtResponse(String jwt) {
        return response()
                .withStatusCode(HttpStatusCode.OK_200.code())
                .withHeader(HTTP.CONTENT_TYPE, "application/jwt")
                .withBody(jwt);
    }

    Map<String, Object> pagedContent(List<String> content, HttpRequest httpRequest) {
        final int requestedPage = parseIntOrDefault(httpRequest.getFirstQueryStringParameter("page"), 0);
        final int requestedSize = parseIntOrDefault(httpRequest.getFirstQueryStringParameter("size"), content.size());

        return Map.of(
                "content", content,
                "page", Map.of(
                        "size", requestedSize,
                        "number", requestedPage,
                        "totalPages", content.isEmpty() ? 0 : 1,
                        "totalElements", content.size()
                )
        );
    }

    private int parseIntOrDefault(String value, int defaultValue) {
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}
