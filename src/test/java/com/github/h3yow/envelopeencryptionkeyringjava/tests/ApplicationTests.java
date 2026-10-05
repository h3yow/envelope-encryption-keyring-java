package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * @author Vincent
 * @version 1.0
 */
@SpringBootTest(properties = {
        "keyring.storage-path=target/application-tests/keyring.json",
        "keyring.root-key=application-tests-root-key",
        "keyring.migration-records-path=target/application-tests/migration-records.json"
})
public class ApplicationTests {
    @Test
    public void contentLoad() {
    }
}
