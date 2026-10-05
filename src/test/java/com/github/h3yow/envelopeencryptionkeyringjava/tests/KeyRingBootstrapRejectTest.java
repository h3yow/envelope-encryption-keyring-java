package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import com.github.h3yow.envelopeencryptionkeyringjava.Application;

/** 缺根口令时必须拒绝启动，绝不退化成明文落盘。 */
class KeyRingBootstrapRejectTest {

    private static final Logger log = LoggerFactory.getLogger(KeyRingBootstrapRejectTest.class);

    @TempDir
    Path dir;

    @Test
    void startupFailsWhenRootPasswordMissingButRequired() {
        var builder = new SpringApplicationBuilder(Application.class)
                .web(WebApplicationType.NONE)
                .properties(
                        "spring.main.web-application-type=none",
                        "keyring.storage-path=" + dir.resolve("keyring.json"),
                        "keyring.migration-store-path=" + dir.resolve("migration-requests.json"),
                        "keyring.admin-token=tok",
                        "keyring.root-password=",
                        "keyring.require-root-password=true",
                        "logging.level.root=WARN");
        boolean failed = false;
        String reason = "";
        try (ConfigurableApplicationContext ctx = builder.run()) {
            ctx.close();
        } catch (RuntimeException ex) {
            failed = true;
            reason = String.valueOf(ex.getMessage());
        }
        log.info("场景-缺根口令拒绝启动 failed={}", failed);
        assertTrue(failed, "缺根口令时上下文启动必须失败");
    }
}
