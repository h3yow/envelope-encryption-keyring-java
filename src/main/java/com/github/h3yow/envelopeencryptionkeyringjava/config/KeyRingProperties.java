package com.github.h3yow.envelopeencryptionkeyringjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** 密钥环相关配置项。 */
@ConfigurationProperties(prefix = "keyring")
public class KeyRingProperties {
    /** 本地密钥环持久化文件路径。 */
    private String storagePath = "./data/keyring.json";
    /** 管理操作令牌；为空时拒绝一切管理操作。 */
    private String adminToken = "";
    /** 是否允许停用最后一个活跃密钥（默认不允许）。 */
    private boolean allowDisableLastActive = false;

    public String getStoragePath() {
        return storagePath;
    }

    public void setStoragePath(String storagePath) {
        this.storagePath = storagePath;
    }

    public String getAdminToken() {
        return adminToken;
    }

    public void setAdminToken(String adminToken) {
        this.adminToken = adminToken;
    }

    public boolean isAllowDisableLastActive() {
        return allowDisableLastActive;
    }

    public void setAllowDisableLastActive(boolean allowDisableLastActive) {
        this.allowDisableLastActive = allowDisableLastActive;
    }
}
