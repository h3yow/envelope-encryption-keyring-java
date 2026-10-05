package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** 上下文可在根口令保护模式下正常启动。 */
@SpringBootTest(properties = {
        "keyring.admin-token=test-admin-token",
        "keyring.root-password=test-root-password"
})
public class ApplicationTests {

    @TempDir
    static Path tempDir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("keyring.storage-path", () -> tempDir.resolve("keyring.json").toString());
        registry.add("keyring.migration-store-path",
                () -> tempDir.resolve("migration-requests.json").toString());
    }

    @Test
    public void contentLoad() {
    }
}
