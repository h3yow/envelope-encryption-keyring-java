package com.github.h3yow.envelopeencryptionkeyringjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** EEKR 可配置项。 */
@ConfigurationProperties(prefix = "eekr")
public record EekrProperties(
        String dataDir,
        String rootKeyPassphrase,
        int kdfIterations,
        String adminToken,
        String userToken,
        Idempotency idempotency) {

    public record Idempotency(int maxRecords) {
    }
}
