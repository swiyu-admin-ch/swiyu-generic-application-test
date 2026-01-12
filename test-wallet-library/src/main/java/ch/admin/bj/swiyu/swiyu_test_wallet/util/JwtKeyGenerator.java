package ch.admin.bj.swiyu.swiyu_test_wallet.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Getter
public class JwtKeyGenerator {

    private final String keyId;
    private final KeyPair keyPair;
    private final String jwksAsJson;
    private final String privateKeyPem;

    public JwtKeyGenerator(String keyId) {
        this.keyId = keyId;
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
            keyPairGen.initialize(ecSpec);
            this.keyPair = keyPairGen.generateKeyPair();

            ECKey ecKey = new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic())
                    .privateKey((ECPrivateKey) keyPair.getPrivate())
                    .keyID(keyId)
                    .algorithm(com.nimbusds.jose.JWSAlgorithm.ES256)
                    .build();

            Map<String, Object> jwk = new LinkedHashMap<>();
            jwk.put("kty", "EC");
            jwk.put("crv", "P-256");
            jwk.put("kid", keyId);
            jwk.put("alg", "ES256");

            ECKey publicKeyOnly = ecKey.toPublicJWK();
            jwk.put("x", publicKeyOnly.getX().toString());
            jwk.put("y", publicKeyOnly.getY().toString());

            Map<String, Object> jwks = new LinkedHashMap<>();
            jwks.put("keys", List.of(jwk));

            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(SerializationFeature.INDENT_OUTPUT);
            this.jwksAsJson = mapper.writeValueAsString(jwks);

            this.privateKeyPem = convertPrivateKeyToPem(keyPair.getPrivate());

            log.info("Generated JWT key with ID: {} (algorithm: ES256, key type: EC, curve: P-256)", keyId);
            log.debug("JWKS: {}", this.jwksAsJson);
        } catch (Exception e) {
            log.error("Failed to generate JWT key", e);
            throw new RuntimeException("Failed to generate JWT key", e);
        }
    }

    public String getJwksAsJson() {
        return jwksAsJson;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public String getKeyId() {
        return keyId;
    }

    public String getPrivateKeyPem() {
        return privateKeyPem;
    }

    private String convertPrivateKeyToPem(PrivateKey privateKey) {
        byte[] encoded = privateKey.getEncoded();
        return "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(encoded) +
                "\n-----END PRIVATE KEY-----";
    }
}





