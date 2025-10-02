package ch.admin.bj.swiyu.swiyu_test_wallet.verifier;

import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

public record VerifierContext(String host, String port) {

    public URI getIssuerUri(String initialUri) {
        return UriComponentsBuilder.fromPath(initialUri).port(port).host(host).build().toUri();
    }

    public URI getIssuerUri(URI initialUri) {
        return UriComponentsBuilder.fromUri(initialUri).port(port).host(host).build().toUri();
    }
}
