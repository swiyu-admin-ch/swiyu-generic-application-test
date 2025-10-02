package ch.admin.bj.swiyu.swiyu_test_wallet;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.LoggingRequestInterceptor;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.ser.InstantSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestClient;

import java.time.Instant;

@SpringBootApplication
public class SwiyuTestWalletApplication {

	public static void main(String[] args) {
		SpringApplication.run(SwiyuTestWalletApplication.class, args);
	}

	@Bean
	public RestClient restClient() {
		var objectMapper = new ObjectMapper();
		RestClient.Builder builder = RestClient.builder();

		builder.requestInterceptor(new LoggingRequestInterceptor());

		builder.messageConverters(c -> {
			c.removeIf(MappingJackson2HttpMessageConverter.class::isInstance);
			c.add(new MappingJackson2HttpMessageConverter(objectMapper));
		});
		return builder.build();
	}
}
