package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.KeyGenerator;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Getter
public class JwtKeyGenerator {

    private final String keyId;
    private final String secret;
    private final String jwksAsJson;

    public JwtKeyGenerator(String keyId) {
        this.keyId = keyId;
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
            keyGen.init(256);
            byte[] secretBytes = keyGen.generateKey().getEncoded();

            this.secret = Base64.getUrlEncoder().withoutPadding().encodeToString(secretBytes);

            Map<String, Object> jwk = new LinkedHashMap<>();
            jwk.put("kty", "oct");  
            jwk.put("kid", keyId);  
            jwk.put("k", this.secret);  
            jwk.put("alg", "HS256");  

            Map<String, Object> jwks = new LinkedHashMap<>();
            jwks.put("keys", List.of(jwk));  

            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(SerializationFeature.INDENT_OUTPUT);
            this.jwksAsJson = mapper.writeValueAsString(jwks);

            log.info("Generated JWT key with ID: {} (algorithm: HS256, key type: oct)", keyId);
            log.debug("JWKS: {}", this.jwksAsJson);
        } catch (Exception e) {
            log.error("Failed to generate JWT key", e);
            throw new RuntimeException("Failed to generate JWT key", e);
        }
    }

    public String getJwksAsJson() {
        return jwksAsJson;
    }

    public String getSecret() {
        return secret;
    }

    public String getKeyId() {
        return keyId;
    }
}





