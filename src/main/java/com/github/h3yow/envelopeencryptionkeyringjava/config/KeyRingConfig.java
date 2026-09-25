package com.github.h3yow.envelopeencryptionkeyringjava.config;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.EnvelopeCipher;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyRing;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.MasterKeyService;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.RewrapService;
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
        return new KeyRing(properties.getStoragePath());
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

    /** 启动时确保密钥环已初始化（无活跃密钥则生成首个主密钥）。 */
    @Bean
    public ApplicationRunner keyRingBootstrap(MasterKeyService masterKeyService) {
        return args -> masterKeyService.ensureInitialized();
    }
}
