package com.github.h3yow.envelopeencryptionkeyringjava.config;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.EnvelopeCipher;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.IdempotentMigrationService;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyMaterialProtector;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyRing;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.MasterKeyService;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.MigrationRequestStore;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.RewrapService;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.KeyRingLockedException;
import java.nio.file.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** 装配密钥环与各服务。 */
@Configuration
@EnableConfigurationProperties(KeyRingProperties.class)
public class KeyRingConfig {

    private static final Logger log = LoggerFactory.getLogger(KeyRingConfig.class);

    @Bean
    public KeyMaterialProtector keyMaterialProtector(KeyRingProperties properties) {
        String rootPassword = properties.getRootPassword();
        boolean blank = rootPassword == null || rootPassword.isBlank();
        if (blank && properties.isRequireRootPassword()) {
            // 拒绝启动，绝不退化成明文落盘
            log.error("AUDIT action=keyring-startup result=rejected reason=missing-root-password");
            throw new KeyRingLockedException(
                    "keyring.root-password is required (set keyring.require-root-password=false only for local legacy use)");
        }
        if (blank) {
            log.warn("AUDIT action=keyring-startup result=degraded protection=plaintext"
                    + " reason=root-password-not-configured");
            return null;
        }
        return new KeyMaterialProtector(rootPassword);
    }

    @Bean
    public KeyRing keyRing(KeyRingProperties properties, KeyMaterialProtector protector) {
        return new KeyRing(properties.getStoragePath(), protector);
    }

    @Bean
    public MasterKeyService masterKeyService(KeyRing keyRing, KeyRingProperties properties) {
        return new MasterKeyService(keyRing, properties.getAdminToken(),
                properties.isAllowDisableLastActive());
    }

    @Bean
    public EnvelopeCipher envelopeCipher(KeyRing keyRing) {
        return new EnvelopeCipher(keyRing);
    }

    @Bean
    public RewrapService rewrapService(KeyRing keyRing) {
        return new RewrapService(keyRing);
    }

    @Bean
    public MigrationRequestStore migrationRequestStore(KeyRingProperties properties) {
        String configured = properties.getMigrationStorePath();
        String path = (configured == null || configured.isBlank())
                ? defaultMigrationPath(properties.getStoragePath())
                : configured;
        return new MigrationRequestStore(path, properties.getMigrationMaxRecords());
    }

    @Bean
    public IdempotentMigrationService idempotentMigrationService(
            RewrapService rewrapService, MigrationRequestStore store) {
        return new IdempotentMigrationService(rewrapService, store);
    }

    private static String defaultMigrationPath(String keyringPath) {
        Path p = Path.of(keyringPath).toAbsolutePath();
        Path dir = p.getParent();
        return (dir == null ? Path.of(".") : dir).resolve("migration-requests.json").toString();
    }

    /** 启动时确保密钥环已初始化（无活跃密钥则生成首个主密钥）。 */
    @Bean
    public ApplicationRunner keyRingBootstrap(MasterKeyService masterKeyService) {
        return args -> masterKeyService.ensureInitialized();
    }
}
