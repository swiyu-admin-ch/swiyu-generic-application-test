package ch.admin.bj.swiyu.swiyu_test_wallet.wallet;

import ch.admin.bj.swiyu.gen.verifier.model.DcqlClaimDto;
import ch.admin.bj.swiyu.swiyu_test_wallet.wallet.credential.DisclosureSelector;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link DisclosureSelector} is a pure function of the credential and the requested claim paths, so it is tested without a
 * Wallet. The expected Disclosures are written from the credential's structure ({@link TestSdJwtVc}).
 */
class DisclosureSelectorTest {

    private TestSdJwtVc credential;

    @BeforeEach
    void setUp() throws Exception {
        credential = TestSdJwtVc.issueFor(new ECKeyGenerator(Curve.P_256).generate());
    }

    private static DcqlClaimDto claim(final Object... path) {
        return new DcqlClaimDto().path(new ArrayList<>(Arrays.asList(path)));
    }

    private List<String> selectedDisclosures(final DcqlClaimDto... claims) {
        final String selected = DisclosureSelector.select(credential.serialized(), List.of(claims));
        assertThat(selected)
                .startsWith(credential.issuerSignedJwt() + "~")
                .endsWith("~");
        final String[] parts = selected.split("~", -1);
        return Arrays.asList(parts).subList(1, parts.length - 1);
    }

    @Test
    void select_whenNothingIsRequested_thenOnlyTheIssuerSignedJwtAndATilde() {
        assertThat(DisclosureSelector.select(credential.serialized(), List.of()))
                .isEqualTo(credential.issuerSignedJwt() + "~");
    }

    @Test
    void select_whenATopLevelClaimIsRequested_thenItsDisclosureOnly() {
        assertThat(selectedDisclosures(claim("name")))
                .containsExactly(credential.nameDisclosure());
    }

    @Test
    void select_whenANestedClaimIsRequested_thenTheParentAndTheClaimButNotTheSiblings() {
        assertThat(selectedDisclosures(claim("address", "locality")))
                .containsExactly(credential.addressDisclosure(), credential.localityDisclosure());
    }

    @Test
    void select_whenAllArrayElementsAreRequested_thenTheArrayAndEveryElement() {
        assertThat(selectedDisclosures(claim("nationalities", null)))
                .containsExactly(credential.nationalitiesDisclosure(), credential.chDisclosure(), credential.frDisclosure());
    }

    @Test
    void select_whenOneArrayElementIsRequestedByIndex_thenTheArrayAndThatElement() {
        assertThat(selectedDisclosures(claim("nationalities", 0)))
                .containsExactly(credential.nationalitiesDisclosure(), credential.chDisclosure());
    }

    @Test
    void select_whenSeveralClaimsAreRequested_thenTheyKeepTheOrderOfTheCredential() {
        assertThat(selectedDisclosures(claim("address", "locality"), claim("name")))
                .containsExactly(credential.nameDisclosure(), credential.addressDisclosure(), credential.localityDisclosure());
    }

    @Test
    void select_whenTheClaimDoesNotExist_thenNothingIsDisclosed() {
        assertThat(selectedDisclosures(claim("does_not_exist")))
                .isEmpty();
    }
}
