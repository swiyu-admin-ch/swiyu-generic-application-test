package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.LoggingRequestInterceptor;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestClient;

@EnableConfigurationProperties
@SpringBootApplication
public class SwiyuTestWalletApplication {

    public static void main(String[] args) {
        SpringApplication.run(SwiyuTestWalletApplication.class, args);
    }

    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    @Bean
    public RestClient.Builder restClientBuilder(ObjectMapper objectMapper) {
        RestClient.Builder builder = RestClient.builder();

        builder.requestInterceptor(new LoggingRequestInterceptor());

        builder.messageConverters(c -> {
            c.removeIf(MappingJackson2HttpMessageConverter.class::isInstance);
            c.add(new MappingJackson2HttpMessageConverter(objectMapper));
        });
        return builder;
    }

    @Bean
    public RestClient restClient(RestClient.Builder restClientBuilder) {
        return restClientBuilder.build();
    }
}
