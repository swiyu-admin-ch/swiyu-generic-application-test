package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.experimental.UtilityClass;

import java.util.List;

@UtilityClass
public class HSMConfig {

    public static final String SIGNING_KEY_METHOD = "pkcs11";
    public static final String PKCS11_CFG = "/tmp/pkcs11.cfg";
    public static final String SOFTHSM_CONF = "/tmp/softhsm2.conf";
    public static final String TOKEN_DIR = "/tmp/softhsm-tokens";
    public static final String LIB_PATH = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so";
    public static final String INIT_SCRIPT = "/usr/local/bin/init-hsm.sh";

    public static final List<Object[]> FILES = List.of(
            new Object[]{"softhsm/libs/libsofthsm2.so", LIB_PATH, 0755},
            new Object[]{"softhsm/libs/libopensc.so.8.0.0", "/lib64/libopensc.so.8", 0755},
            new Object[]{"softhsm/bins/pkcs11-tool", "/usr/local/bin/pkcs11-tool", 0755},
            new Object[]{"softhsm/bins/softhsm2-util", "/usr/local/bin/softhsm2-util", 0755},
            new Object[]{"softhsm/pkcs11.cfg", PKCS11_CFG, 0644},
            new Object[]{"softhsm/softhsm2.conf", SOFTHSM_CONF, 0644},
            new Object[]{"softhsm/init-hsm.sh", INIT_SCRIPT, 0755}
    );

}
