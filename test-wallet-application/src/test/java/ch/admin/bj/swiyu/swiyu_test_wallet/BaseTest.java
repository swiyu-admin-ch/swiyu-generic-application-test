package ch.admin.bj.swiyu.swiyu_test_wallet;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
        properties = {
                "server.port=${systemtests.port:18888}",
                "server.address=0.0.0.0"
        },
        classes = SwiyuTestWalletApplication.class
)
@ActiveProfiles("systemtests")
public class BaseTest { }
