package ch.admin.bj.swiyu.swiyu_test_wallet.fixture;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class CredentialClaimsFixtures {

    public static Map<String, Object> createBaseProfile() {
        final Map<String, Object> claims = new HashMap<>();

        claims.put(CredentialClaimsConstants.KEY_NAME, CredentialClaimsConstants.DEFAULT_NAME);

        final Map<String, Object> address = new HashMap<>();
        address.put(CredentialClaimsConstants.KEY_ADDRESS_STREET_ADDRESS, CredentialClaimsConstants.DEFAULT_STREET);
        address.put(CredentialClaimsConstants.KEY_ADDRESS_LOCALITY, CredentialClaimsConstants.DEFAULT_LOCALITY);
        address.put(CredentialClaimsConstants.KEY_ADDRESS_POSTAL_CODE, CredentialClaimsConstants.DEFAULT_POSTAL_CODE);
        claims.put(CredentialClaimsConstants.KEY_ADDRESS, address);

        final List<Map<String, Object>> degrees = new ArrayList<>();

        final Map<String, Object> degree1 = new HashMap<>();
        degree1.put(CredentialClaimsConstants.KEY_DEGREE_TYPE, CredentialClaimsConstants.DEGREE_TYPE_BACHELOR);
        degree1.put(CredentialClaimsConstants.KEY_DEGREE_UNIVERSITY, CredentialClaimsConstants.DEFAULT_UNIVERSITY);

        final Map<String, Object> degree2 = new HashMap<>();
        degree2.put(CredentialClaimsConstants.KEY_DEGREE_TYPE, CredentialClaimsConstants.DEGREE_TYPE_MASTER);
        degree2.put(CredentialClaimsConstants.KEY_DEGREE_UNIVERSITY, CredentialClaimsConstants.DEFAULT_UNIVERSITY);

        degrees.add(degree1);
        degrees.add(degree2);

        claims.put(CredentialClaimsConstants.KEY_DEGREES, degrees);
        claims.put(CredentialClaimsConstants.KEY_NATIONALITIES, CredentialClaimsConstants.DEFAULT_NATIONALITIES);
        claims.put(CredentialClaimsConstants.KEY_BIRTH_YEAR, CredentialClaimsConstants.DEFAULT_BIRTH_YEAR);
        claims.put(CredentialClaimsConstants.KEY_FAVORITE_NUMBERS, CredentialClaimsConstants.DEFAULT_FAVORITE_NUMBERS);
        claims.put(CredentialClaimsConstants.KEY_PORTRAIT, CredentialClaimsConstants.DEFAULT_PORTRAIT);
        claims.put(CredentialClaimsConstants.KEY_ADDITIONAL_INFO, CredentialClaimsConstants.DEFAULT_ADDITIONAL_INFO);
        claims.put(CredentialClaimsConstants.KEY_ADDITIONAL_INFO_LIST, CredentialClaimsConstants.DEFAULT_ADDITIONAL_INFO_LIST);

        return claims;
    }

    public static Map<String, Object> setValue(
            Map<String, Object> base,
            String key,
            Object value
    ) {
        final Map<String, Object> copy = new HashMap<>(base);
        copy.put(key, value);
        return copy;
    }

    public static Map<String, Object> removeKey(
            Map<String, Object> base,
            String key
    ) {
        final Map<String, Object> copy = new HashMap<>(base);
        copy.remove(key);
        return copy;
    }

    public static Map<String, Object> setNull(
            Map<String, Object> base,
            String key
    ) {
        return setValue(base, key, null);
    }

    public static Map<String, Object> setEmptyArray(
            Map<String, Object> base,
            String key
    ) {
        return setValue(base, key, List.of());
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> addToArray(
            Map<String, Object> base,
            String key,
            Object element
    ) {
        final Map<String, Object> copy = new HashMap<>(base);

        final List<Object> list = new ArrayList<>(
                (List<Object>) copy.getOrDefault(key, new ArrayList<>())
        );

        list.add(element);
        copy.put(key, list);

        return copy;
    }

    public static Map<String, Object> setArray(
            Map<String, Object> base,
            String key,
            List<?> values
    ) {
        return setValue(base, key, values);
    }

}
