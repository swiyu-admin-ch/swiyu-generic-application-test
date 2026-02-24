package ch.admin.bj.swiyu.swiyu_test_wallet.exceptions;

public class WalletEncryptionException extends RuntimeException {

    public WalletEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

    public WalletEncryptionException(String message) {
        super(message);
    }

}