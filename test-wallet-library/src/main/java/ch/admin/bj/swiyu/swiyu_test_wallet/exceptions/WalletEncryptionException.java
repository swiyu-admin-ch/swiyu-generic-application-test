package ch.admin.bj.swiyu.swiyu_test_wallet.exceptions;

import java.io.Serial;

public class WalletEncryptionException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    public WalletEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

    public WalletEncryptionException(String message) {
        super(message);
    }

}
