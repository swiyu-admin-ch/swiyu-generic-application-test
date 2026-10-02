package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.sdjwtverifier.SdJwt;
import ch.admin.bj.swiyu.sdjwtverifier.SdJwtParser;
import ch.admin.bj.swiyu.sdjwtverifier.SdJwtVcValidator;
import com.nimbusds.jose.jwk.ECKey;

import java.util.Map;

import static org.mockito.Mockito.mock;

/**
 * The only place where wallet unit tests use the SD-JWT verification code of {@code swiyu-generic-java-lib}.
 *
 * <p>Role: reference, in unit tests only. The Verifier under test uses the same library, so a presentation accepted
 * here is a presentation the Verifier's validators accept. It must never decide what the wallet produces: the expected
 * values in the tests are written from RFC 9901. The library modules involved are marked draft, hence this adapter.
 *
 * <p>The issuer signature itself is not checked here ({@link DidJwtValidator} is mocked); the tests build the
 * credential themselves and never alter the issuer-signed JWT.
 */
final class SdJwtLibReference {

    private static final int ACCEPTABLE_KEY_BINDING_WINDOW_SECONDS = 60;

    private SdJwtLibReference() {
    }

    /**
     * Runs the Verifier-side checks on a presentation: parse, header, claims, Key Binding JWT (signature, {@code typ},
     * {@code aud}, {@code nonce}, {@code sd_hash}, freshness), and Disclosure processing.
     *
     * @return the claims resolved from the Disclosures that are present in the presentation
     * @throws Exception when any of the Verifier-side checks rejects the presentation
     */
    static Map<String, Object> verifyAndResolveClaims(
            final String presentation,
            final ECKey issuerKey,
            final String audience,
            final String nonce
    ) throws Exception {
        final SdJwtVcValidator validator = new SdJwtVcValidator(mock(DidJwtValidator.class));
        final SdJwt sdJwt = SdJwtParser.parseSdJwt(presentation);
        validator.validateAndSetHeader(sdJwt);
        validator.validateAndSetJwt(sdJwt, issuerKey);
        validator.validateKeyBinding(sdJwt, audience, nonce, ACCEPTABLE_KEY_BINDING_WINDOW_SECONDS);
        return validator.processDisclosures(sdJwt);
    }
}
