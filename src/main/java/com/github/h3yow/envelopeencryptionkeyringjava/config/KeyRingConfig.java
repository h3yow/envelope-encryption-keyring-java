package com.github.h3yow.envelopeencryptionkeyringjava.config;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.EnvelopeCipher;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyRing;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyRingProtection;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.MasterKeyService;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.RewrapService;
import com.github.h3yow.envelopeencryptionkeyringjava.migration.MigrationRecordStore;
import com.github.h3yow.envelopeencryptionkeyringjava.migration.MigrationService;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** 装配密钥环与各服务。 */
@Configuration
@EnableConfigurationProperties(KeyRingProperties.class)
public class KeyRingConfig {

    @Bean
    public KeyRing keyRing(KeyRingProperties properties) {
        // 根口令缺失时 fromRootKey 直接拒绝，应用启动失败，绝不退化为明文落盘
        return new KeyRing(properties.getStoragePath(),
                KeyRingProtection.fromRootKey(properties.getRootKey()));
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
    public MigrationRecordStore migrationRecordStore(KeyRingProperties properties) {
        return new MigrationRecordStore(properties.getMigrationRecordsPath(),
                properties.getMigrationMaxRecords());
    }

    @Bean
    public MigrationService migrationService(RewrapService rewrapService,
                                             MigrationRecordStore migrationRecordStore) {
        return new MigrationService(rewrapService, migrationRecordStore);
    }

    /** 启动时确保密钥环已初始化（无活跃密钥则生成首个主密钥）。 */
    @Bean
    public ApplicationRunner keyRingBootstrap(MasterKeyService masterKeyService) {
        return args -> masterKeyService.ensureInitialized();
    }
}
