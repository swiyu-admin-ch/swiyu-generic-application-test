package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.util.StreamUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Slf4j
public class HttpTraceInterceptor implements ClientHttpRequestInterceptor {

    /**
     * Headers explicitly allowed to appear in trace logs.
     */
    private static final Set<String> TRACEABLE_HEADERS = Set.of(
            "content-type",
            "accept",
            "authorization",
            "swiyu-api-version",
            "dpop",
            "content-length"
    );

    private static final String JSON_CODE_BLOCK_DELIMITER = "\n```";

    private final File outputFile;
    private final String prefix;

    public HttpTraceInterceptor(File outputFile, final String prefix) {
        this.outputFile = outputFile;
        this.prefix = prefix;
    }

    private void append(String text) {
        try (FileWriter fw = new FileWriter(outputFile, true)) {
            fw.write(text + System.lineSeparator());
        } catch (Exception e) {
            log.error("Failed to write HTTP trace", e);
        }
    }

    private String formatFilteredHeaders(HttpHeaders headers) {
        StringBuilder sb = new StringBuilder();

        headers.forEach((key, values) -> {
            if (TRACEABLE_HEADERS.contains(key.toLowerCase())) {
                sb.append("_")
                        .append(key.toLowerCase())
                        .append("_: ")
                        .append(String.join(", ", values))
                        .append(" \\\n");
            }
        });

        return sb.length() == 0 ? "_<no allowed headers>_" : sb.toString().trim();
    }


    @Override
    public ClientHttpResponse intercept(
            HttpRequest request,
            byte[] body,
            ClientHttpRequestExecution execution
    ) throws IOException {

        append("# Request " + prefix);
        append("");

        append("## Request");
        append("");
        append("**Target** \\");
        append(request.getMethod() + " " + request.getURI());
        append("");

        append("**Headers** \\");
        append(formatFilteredHeaders(request.getHeaders()));
        append("");

        append("**Body**");
        append(formatBodyAsJsonBlock(body));
        append("");

        ClientHttpResponse response = execution.execute(request, body);
        var data = response.getBody();
        byte[] respBody = StreamUtils.copyToByteArray(data);

        append("## Response");
        append("");
        append("**Status:** \\");
        append(response.getStatusCode().value() + " " + response.getStatusText());
        append("");

        append("**Headers** \\");
        append(formatFilteredHeaders(response.getHeaders()));
        append("");

        append("**Body**");
        append(formatBodyAsJsonBlock(respBody));
        append("\n---\n");

        return new BufferingClientHttpResponseWrapper(response, respBody);
    }

    private String formatBodyAsJsonBlock(byte[] bodyBytes) {
        if (bodyBytes == null || bodyBytes.length == 0)
            return "```json\n{}" + JSON_CODE_BLOCK_DELIMITER;

        String raw = new String(bodyBytes, StandardCharsets.UTF_8).trim();
        return "```json\n" + raw + JSON_CODE_BLOCK_DELIMITER;
    }


    private static class BufferingClientHttpResponseWrapper implements ClientHttpResponse {
        private final ClientHttpResponse response;
        private final byte[] body;

        BufferingClientHttpResponseWrapper(ClientHttpResponse response, byte[] body) {
            this.response = response;
            this.body = body;
        }

        @Override public InputStream getBody() { return new ByteArrayInputStream(body); }
        @Override public HttpHeaders getHeaders() { return response.getHeaders(); }
        @Override public HttpStatusCode getStatusCode() throws IOException { return response.getStatusCode(); }
        @Override public String getStatusText() throws IOException { return response.getStatusText(); }
        @Override public void close() { response.close(); }
    }
}
