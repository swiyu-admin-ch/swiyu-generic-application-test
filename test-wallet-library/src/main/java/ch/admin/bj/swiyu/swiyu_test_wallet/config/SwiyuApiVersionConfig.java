package ch.admin.bj.swiyu.swiyu_test_wallet.config;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum SwiyuApiVersionConfig {

    ID2("1"),
    V1("2");

    private final String value;

    @Override
    public String toString() {
        return value;
    }
}
