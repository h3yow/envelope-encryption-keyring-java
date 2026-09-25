package com.github.h3yow.envelopeencryptionkeyringjava.config;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CryptoService;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;

/** Bean 装配入口。 */
@Configuration
@ConfigurationPropertiesScan
public class AppConfig {

    /** AES-GCM/PBKDF2 原语。 */
    @Bean
    public CryptoService cryptoService() {
        return new CryptoService();
    }

    /** 密钥环 JSON 文件位置。 */
    @Bean(name = "keyRingFile")
    public Path keyRingFile(EekrProperties props) {
        return Path.of(props.dataDir(), "keyring.json");
    }

    /** 重包裹幂等记录目录。 */
    @Bean(name = "rewrapDir")
    public Path rewrapDir(EekrProperties props) {
        return Path.of(props.dataDir(), "rewraps");
    }
}
