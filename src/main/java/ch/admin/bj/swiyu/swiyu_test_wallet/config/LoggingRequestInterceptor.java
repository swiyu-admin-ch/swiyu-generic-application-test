package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
public class LoggingRequestInterceptor implements ClientHttpRequestInterceptor {
    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
        logRequestHeaderAndBody(request, body);
        return execution.execute(request, body);
    }

    private void logRequestHeaderAndBody(HttpRequest request, byte[] body) {
        String bodyContent = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(body), UTF_8))
                .lines()
                .collect(Collectors.joining("\n"));
        HttpHeaders headers = request.getHeaders();

        log.info("Request: {} {} with headers {} and body '{}'", request.getMethod(), request.getURI(), headers, bodyContent);
    }
}
