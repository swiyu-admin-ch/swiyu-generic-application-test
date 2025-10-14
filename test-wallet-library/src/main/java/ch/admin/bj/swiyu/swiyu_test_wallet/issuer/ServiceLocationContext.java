package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

public record ServiceLocationContext(String issuerHost, String issuerPort) {

    public URI getContextualizedUri(URI initialUri) {
        return UriComponentsBuilder.fromUri(initialUri).port(issuerPort).host(issuerHost).build().toUri();
    }
}
