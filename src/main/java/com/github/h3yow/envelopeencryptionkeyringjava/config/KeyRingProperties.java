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
    /** 密钥环落盘保护根口令；为空且 require-root-password=true 时拒绝启动。 */
    private String rootPassword = "";
    /** 是否强制要求根口令（不允许退化成明文落盘）。 */
    private boolean requireRootPassword = true;
    /** 迁移幂等记录持久化文件路径；为空时取密钥环同目录下的 migration-requests.json。 */
    private String migrationStorePath = "";
    /** 迁移幂等记录上限；超过后按确定性规则淘汰最旧（最久未重放）记录。 */
    private int migrationMaxRecords = 1000;

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

    public String getRootPassword() {
        return rootPassword;
    }

    public void setRootPassword(String rootPassword) {
        this.rootPassword = rootPassword;
    }

    public boolean isRequireRootPassword() {
        return requireRootPassword;
    }

    public void setRequireRootPassword(boolean requireRootPassword) {
        this.requireRootPassword = requireRootPassword;
    }

    public String getMigrationStorePath() {
        return migrationStorePath;
    }

    public void setMigrationStorePath(String migrationStorePath) {
        this.migrationStorePath = migrationStorePath;
    }

    public int getMigrationMaxRecords() {
        return migrationMaxRecords;
    }

    public void setMigrationMaxRecords(int migrationMaxRecords) {
        this.migrationMaxRecords = migrationMaxRecords;
    }
}
