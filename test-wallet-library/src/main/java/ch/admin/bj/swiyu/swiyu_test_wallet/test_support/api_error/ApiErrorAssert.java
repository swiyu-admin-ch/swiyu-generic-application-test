package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.api_error;

import java.util.Map;

import org.assertj.core.api.Assertions;
import org.springframework.web.client.HttpClientErrorException;

import com.fasterxml.jackson.databind.ObjectMapper;

public final class ApiErrorAssert {

    private final HttpClientErrorException exception;
    private final Map<String, Object> errorBody;

    private ApiErrorAssert(final HttpClientErrorException exception) {
        this.exception = exception;
        this.errorBody = parseErrorBody(exception);
    }

    public static ApiErrorAssert assertThat(
            final HttpClientErrorException exception
    ) {
        return new ApiErrorAssert(exception);
    }

    public ApiErrorAssert hasStatus(final int expectedStatus) {
        Assertions.assertThat(exception.getStatusCode().value())
                .as("HTTP status code")
                .isEqualTo(expectedStatus);
        return this;
    }

    public ApiErrorAssert hasError(final String expectedError) {
        Assertions.assertThat(errorBody)
                .as("error field")
                .containsEntry("error", expectedError);
        return this;
    }

    public ApiErrorAssert hasErrorDescription(final String expectedDescription) {
        Assertions.assertThat(errorBody)
                .as("error_description field")
                .containsEntry("error_description", expectedDescription);
        return this;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parseErrorBody(
            final HttpClientErrorException exception
    ) {
        try {
            return new ObjectMapper()
                    .readValue(exception.getResponseBodyAsString(), Map.class);
        } catch (Exception e) {
            throw new AssertionError(
                    "Failed to parse error response body as JSON",
                    e
            );
        }
    }
}

