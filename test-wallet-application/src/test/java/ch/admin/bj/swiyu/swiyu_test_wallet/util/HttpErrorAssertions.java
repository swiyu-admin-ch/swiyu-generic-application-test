package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.springframework.web.client.HttpClientErrorException;

public class HttpErrorAssertions {

    public static int errorCode(HttpClientErrorException exception) {
        return exception.getStatusCode().value();
    }

    public static JsonObject errorJson(HttpClientErrorException exception) {
        String body = exception.getResponseBodyAsString();
        return JsonParser.parseString(body).getAsJsonObject();
    }
}

