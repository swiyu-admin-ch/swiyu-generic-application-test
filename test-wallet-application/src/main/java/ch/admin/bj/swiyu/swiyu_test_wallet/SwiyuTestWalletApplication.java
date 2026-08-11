package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.LoggingRequestInterceptor;
import tools.jackson.databind.json.JsonMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.web.client.RestClient;

@EnableConfigurationProperties
@SpringBootApplication
public class SwiyuTestWalletApplication {

    public static void main(String[] args) {
        SpringApplication.run(SwiyuTestWalletApplication.class, args);
    }

    @Bean
    public RestClient restClient() {
        var jsonMapper = JsonMapper.builder().build();
        RestClient.Builder builder = RestClient.builder();

        builder.requestInterceptor(new LoggingRequestInterceptor());

        builder.configureMessageConverters(
                converters -> converters.addCustomConverter(new JacksonJsonHttpMessageConverter(jsonMapper))
        );
        return builder.build();
    }
}
