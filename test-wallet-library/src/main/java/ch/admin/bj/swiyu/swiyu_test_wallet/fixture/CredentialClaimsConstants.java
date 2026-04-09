package ch.admin.bj.swiyu.swiyu_test_wallet.fixture;

import lombok.experimental.UtilityClass;

import java.util.Arrays;
import java.util.List;

@UtilityClass
public class CredentialClaimsConstants {

    public static final String KEY_NAME = "name";
    public static final String KEY_ADDRESS = "address";
    public static final String KEY_ADDRESS_STREET_ADDRESS = "street_address";
    public static final String KEY_ADDRESS_LOCALITY = "locality";
    public static final String KEY_ADDRESS_POSTAL_CODE = "postal_code";
    public static final String KEY_DEGREES = "degrees";
    public static final String KEY_DEGREE_TYPE = "type";
    public static final String KEY_DEGREE_UNIVERSITY = "university";
    public static final String KEY_NATIONALITIES = "nationalities";
    public static final String KEY_BIRTH_YEAR = "birth_year";
    public static final String KEY_FAVORITE_NUMBERS = "favorite_numbers";
    public static final String KEY_PORTRAIT = "portrait";
    public static final String KEY_ADDITIONAL_INFO = "additional_info";
    public static final String KEY_ADDITIONAL_INFO_LIST = "additional_info_list";

    public static final String DEFAULT_NAME = "John Doe";
    public static final String DEFAULT_STREET = "42 Market Street";
    public static final String DEFAULT_LOCALITY = "Milliways";
    public static final String DEFAULT_POSTAL_CODE = "12345";
    public static final String DEGREE_TYPE_BACHELOR = "Bachelor of Science";
    public static final String DEGREE_TYPE_MASTER = "Master of Science";
    public static final String DEFAULT_UNIVERSITY = "University of Betelgeuse";
    public static final List<String> DEFAULT_NATIONALITIES =
            Arrays.asList("British", "Betelgeusian");
    public static final Integer DEFAULT_BIRTH_YEAR = 1978;
    public static final List<Integer> DEFAULT_FAVORITE_NUMBERS =
            Arrays.asList(3, 7, 42);
    public static final String DEFAULT_PORTRAIT =
            "https://example.com/images/portrait.png";
    public static final String DEFAULT_ADDITIONAL_INFO = "some-random-value";
    public static final List<Object> DEFAULT_ADDITIONAL_INFO_LIST =
            Arrays.asList("string", 123, true, null);

}
