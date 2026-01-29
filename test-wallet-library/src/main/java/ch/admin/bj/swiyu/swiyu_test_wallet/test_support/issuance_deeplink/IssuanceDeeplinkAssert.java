package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.issuance_deeplink;

import com.jayway.jsonpath.JsonPath;

import lombok.extern.slf4j.Slf4j;

import org.assertj.core.api.Assertions;

import java.util.List;

@Slf4j
public final class IssuanceDeeplinkAssert {

    private final String credentialOfferJson;

    private IssuanceDeeplinkAssert(final String deeplink) {
        this.credentialOfferJson = IssuanceDeeplinkParser.extractCredentialOfferJson(deeplink);
    }

    public static IssuanceDeeplinkAssert assertThat(final String deeplink) {
        final IssuanceDeeplinkAssert issuanceDeeplinkAssert = new IssuanceDeeplinkAssert(deeplink);
        log.debug(String.format("Deeplink [%s]", deeplink));
        log.debug(String.format("\tIssuanceDeeplinkAssert [%s]", issuanceDeeplinkAssert.credentialOfferJson));
        return issuanceDeeplinkAssert;
    }

    public IssuanceDeeplinkAssert isWellFormed() {
        Assertions.assertThat(credentialOfferJson)
                .as("Issuance deeplink must contain credential_offer")
                .isNotBlank();
        return this;
    }

    public IssuanceDeeplinkAssert hasVersion(final String expectedVersion) {
        final String version = JsonPath.read(credentialOfferJson, "$.version");

        Assertions.assertThat(version)
                .as("credential_offer.version")
                .isEqualTo(expectedVersion);
        return this;
    }

    public IssuanceDeeplinkAssert hasCredentialIssuer(
            final String expectedIssuer) {
        final String issuer = JsonPath.read(
                credentialOfferJson,
                "$.credential_issuer");

        Assertions.assertThat(issuer)
                .as("credential_offer.credential_issuer")
                .isEqualTo(expectedIssuer);
        return this;
    }

    public IssuanceDeeplinkAssert containsCredentialConfigurationId(
            final String expectedId) {
        final List<String> ids = JsonPath.read(
                credentialOfferJson,
                "$.credential_configuration_ids");

        Assertions.assertThat(ids)
                .as("credential_offer.credential_configuration_ids")
                .contains(expectedId);
        return this;
    }
}
