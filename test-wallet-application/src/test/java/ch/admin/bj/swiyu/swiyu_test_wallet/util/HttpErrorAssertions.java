package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Map;

public class HttpErrorAssertions {

    @SuppressWarnings("unchecked")
    public static Map<String, String> errorJson(HttpClientErrorException ex) {
        return (Map<String, String>) ex.getResponseBodyAs(Map.class);
    }

    @SuppressWarnings("unchecked")
    public static int errorCode(HttpClientErrorException ex) {
        return ex.getStatusCode().value();
    }
}

