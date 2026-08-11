package ch.admin.bj.swiyu.swiyu_test_wallet.config.tp2;

import ch.admin.bj.swiyu.swiyu_test_wallet.test_support.TestSupportException;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.protocol.HTTP;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.HttpStatusCode;

import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

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
        } catch (JacksonException e) {
            throw new TestSupportException("Cannot serialize MockServer response: " + e.getMessage());
        }
    }

    HttpResponse jwtResponse(String jwt) {
        return response()
                .withStatusCode(HttpStatusCode.OK_200.code())
                .withHeader(HTTP.CONTENT_TYPE, "application/jwt")
                .withBody(jwt);
    }

    HttpResponse statusListJwtResponse(String jwt) {
        return response()
                .withStatusCode(HttpStatusCode.OK_200.code())
                .withHeader(HTTP.CONTENT_TYPE, "application/statuslist+jwt")
                .withBody(jwt);
    }

    HttpResponse badRequestResponse(String message) {
        return jsonErrorResponse(HttpStatusCode.BAD_REQUEST_400, message);
    }

    HttpResponse unauthorizedResponse(String message) {
        return jsonErrorResponse(HttpStatusCode.UNAUTHORIZED_401, message);
    }

    HttpResponse notFoundResponse(String message) {
        return jsonErrorResponse(HttpStatusCode.NOT_FOUND_404, message);
    }

    HttpResponse vqpsSubmissionSuccessResponse(String vqPs) {
        try {
            SignedJWT statement = SignedJWT.parse(vqPs);
            String now = Instant.now().toString();
            return jsonResponse(Map.of(
                    "id", UUID.randomUUID().toString(),
                    "partnerId", UUID.randomUUID().toString(),
                    "version", 1,
                    "status", "PUBLICATION_SUCCEEDED",
                    "publicationResult", Map.of(
                            "jti", statement.getJWTClaimsSet().getJWTID(),
                            "jwt", vqPs,
                            "expiresAt", statement.getJWTClaimsSet().getExpirationTime().toInstant().toString()
                    ),
                    "createdAt", now,
                    "updatedAt", now
            ));
        } catch (ParseException e) {
            throw new TestSupportException("Cannot parse published vqPS JWT: " + e.getMessage());
        }
    }

    HttpResponse tmsValidationErrorResponse(String message, String field, String error) {
        return response()
                .withStatusCode(HttpStatusCode.BAD_REQUEST_400.code())
                .withHeader(HTTP.CONTENT_TYPE, "application/json")
                .withBody("""
                        {"status":"error","message":"%s","details":[{"field":"%s","error":"%s"}]}\
                        """.formatted(message, field, error));
    }

    Map<String, Object> requestBodyAsMap(HttpRequest request) {
        try {
            return objectMapper.readValue(request.getBodyAsString(), new TypeReference<>() {
            });
        } catch (JacksonException e) {
            throw new IllegalArgumentException("request body must be a JSON object");
        }
    }

    private HttpResponse jsonErrorResponse(HttpStatusCode statusCode, String message) {
        return response()
                .withStatusCode(statusCode.code())
                .withHeader(HTTP.CONTENT_TYPE, "application/json")
                .withBody("{\"error\":\"%s\"}".formatted(message));
    }

    Map<String, Object> pagedContent(List<String> content, HttpRequest httpRequest) {
        final int requestedPage = Math.max(parseIntOrDefault(httpRequest.getFirstQueryStringParameter("page"), 0), 0);
        final int requestedSize = Math.max(parseIntOrDefault(httpRequest.getFirstQueryStringParameter("size"), 20), 1);
        final int fromIndex = Math.min(requestedPage * requestedSize, content.size());
        final int toIndex = Math.min(fromIndex + requestedSize, content.size());
        final List<String> pageContent = content.subList(fromIndex, toIndex);

        return Map.of(
                "content", pageContent,
                "page", Map.of(
                        "size", pageContent.size(),
                        "number", requestedPage,
                        "totalPages", content.isEmpty() ? 0 : (int) Math.ceil((double) content.size() / requestedSize),
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
