package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Slf4j
public class JwtAuthInterceptor implements ClientHttpRequestInterceptor {

    private final String jwtSecret;
    private final String keyId;
    private final byte[] secretBytes;

    public JwtAuthInterceptor(String jwtSecret, String keyId) {
        this.jwtSecret = jwtSecret;
        this.keyId = keyId;
        try {
            this.secretBytes = Base64.getUrlDecoder().decode(jwtSecret);
            log.debug("Successfully decoded JWT secret, {} bytes", secretBytes.length);
        } catch (IllegalArgumentException e) {
            log.error("Failed to decode JWT secret as Base64-URL", e);
            throw new RuntimeException("Invalid Base64-URL encoded secret: " + e.getMessage(), e);
        }
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
        log.debug("JwtAuthInterceptor.intercept() called for {}", request.getURI());
        log.debug("Request method: {}", request.getMethod());
        log.debug("Request body length: {}", body != null ? body.length : 0);

        try {
            String jwt = createJwt();
            log.debug("JWT created successfully, length: {}", jwt.length());
            log.debug("JWT content (first 50 chars): {}", jwt.substring(0, Math.min(50, jwt.length())));

            byte[] jwtBytes = jwt.getBytes();
            log.debug("JWT bytes prepared, length: {}", jwtBytes.length);

            ClientHttpResponse response = execution.execute(request, jwtBytes);
            log.debug("Request executed successfully");
            return response;

        } catch (Exception e) {
            log.error("Error in JwtAuthInterceptor", e);
            throw new IOException("JWT generation failed", e);
        }
    }

    public String createJwt() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .keyID(keyId)
                .build();

        Date now = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600000))
                .subject("test-issuer")
                .audience("issuer-api")
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        JWSSigner signer = new MACSigner(secretBytes);
        signedJWT.sign(signer);

        String jwtToken = signedJWT.serialize();
        log.debug("Generated JWT with {} parts", jwtToken.split("\\.").length);
        log.trace("JWT: {}", jwtToken);

        return jwtToken;
    }
}



