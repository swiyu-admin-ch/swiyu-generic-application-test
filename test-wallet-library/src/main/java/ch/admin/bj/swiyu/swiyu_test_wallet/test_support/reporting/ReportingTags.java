package ch.admin.bj.swiyu.swiyu_test_wallet.test_support.reporting;

import lombok.experimental.UtilityClass;

/** JUnit reporting tags with stable use-case identifiers. */
@UtilityClass
public class ReportingTags {

    public static final String HAPPY_PATH = "happy_path";
    public static final String EDGE_CASE = "edge_case";

    public static final String TEST_REGRESSION = "version_regression";
    public static final String TEST_HSM = "test_hsm";

    // Issuer use cases
    public static final String UCI_EX_1_DISPLAY_QR_CODE_TO_GET_CREDENTIAL_OFFER = "uci_ex_1";
    public static final String UCI_EX_2_SCAN_QR_CODE_AND_FETCH_DEEPLINK = "uci_ex_2";
    public static final String UCI_S1_CREATE_STATUS_LIST = "uci_s1";
    public static final String UCI_S2_RETRIEVE_STATUS_LIST = "uci_s2";
    public static final String UCI_C1_CREATE_A_GENERIC_CREDENTIAL_OFFER = "uci_c1";
    public static final String UCI_C1A_CREATE_A_DEEPLINK_FOR_CREDENTIAL_OFFER = "uci_c1a";
    public static final String UCI_C1B_STORE_THE_CREDENTIAL_OFFER_IN_THE_DATABASE = "uci_c1b";
    public static final String UCI_C2_GET_THE_CURRENT_STATUS_OF_AN_OFFER = "uci_c2";
    public static final String UCI_C3_UPDATE_THE_STATUS_OF_AN_OFFER_OR_VC = "uci_c3";
    public static final String UCI_W1_EXPOSE_OPENID_WELL_KNOWN_ENDPOINTS = "uci_w1";
    public static final String UCI_W1A_EXPOSE_TOKEN_ENDPOINT = "uci_w1a";
    public static final String UCI_M1_PROVIDE_METADATA_RELATED_TO_VCS = "uci_m1";
    public static final String UCI_M1A_EXPOSE_CREDENTIAL_TYPE_METADATA = "uci_m1a";
    public static final String UCI_I1_ISSUING_VERIFIABLE_CREDENTIALS = "uci_i1";
    public static final String UCI_I1A_CREATE_VERIFIABLE_CREDENTIALS = "uci_i1a";
    public static final String UCI_I1B_CREATE_DEFERRED_VERIFIABLE_CREDENTIALS = "uci_i1b";
    public static final String UCI_I1C_STORE_THE_VERIFIABLE_CREDENTIAL = "uci_i1c";
    public static final String UCI_I1D_CREATE_WEBHOOK_STATUS_CHANGE = "uci_i1d";
    public static final String UCI_I1E_RENEW_VERIFIABLE_CREDENTIALS = "uci_i1e";
    public static final String UCI_I2_GET_AUTHORIZATION_FOR_ISSUING = "uci_i2";
    public static final String UCI_P1_GET_JWT_FOR_ACCESSING = "uci_p1";

    // Verifier use cases
    public static final String UCV_E1_DISPLAY_QR_CODE_FOR_VERIFICATION = "ucv_e1";
    public static final String UCV_E2_SCAN_QR_CODE_AND_FETCH_DEEPLINK = "ucv_e2";
    public static final String UCV_O1_REQUEST_VERIFICATION_OBJECT = "ucv_o1";
    public static final String UCV_O1A_CREATE_SIGNED_REQUEST_OBJECT = "ucv_o1a";
    public static final String UCV_O1B_CREATE_UNSIGNED_REQUEST_OBJECT = "ucv_o1b";
    public static final String UCV_O1C_EMBED_TRUST_STATEMENTS_IN_VERIFIER_INFO = "ucv_o1c";
    public static final String UCV_O2_SUBMIT_VERIFICATION_PRESENTATION = "ucv_o2";
    public static final String UCV_O2A_VERIFY_PRESENTATION_SUBMISSION_AND_SD_JWT_CREDENTIAL = "ucv_o2a";
    public static final String UCV_O2C_CHECK_VC_STATUS_IN_REGISTRY = "ucv_o2c";
    public static final String UCV_O2D_STORE_VERIFICATION_RESULT = "ucv_o2d";
    public static final String UCV_O2E_TRIGGER_WEBHOOK_CALLBACK = "ucv_o2e";
    public static final String UCV_O2F_VALIDATE_ISSUER_VIA_TRUST_REGISTRY_TP2_VERIFIER_VIEW = "ucv_o2f";
    public static final String UCV_M1_INITIATE_VERIFICATION_PROCESS = "ucv_m1";
    public static final String UCV_M1A_CREATE_VERIFICATION_MANAGEMENT_ENTRY = "ucv_m1a";
    public static final String UCV_M1B_PROVIDE_DEEPLINK_FOR_QR_CODE = "ucv_m1b";
    public static final String UCV_M1C_REGISTER_VQPS_ON_THE_FLY = "ucv_m1c";
    public static final String UCV_M3_RETRIEVE_VERIFICATION_RESULT = "ucv_m3";
    public static final String UCV_M4_RETRIEVE_FULL_VERIFIABLE_PRESENTATION_EXTENDED_NON_REPUDIATION = "ucv_m4";
}
