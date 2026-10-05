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
    /** 根口令：派生根密钥包裹主密钥材料后落盘；为空时拒绝启动，绝不退化为明文。 */
    private String rootKey = "";
    /** 迁移请求记录持久化文件路径。 */
    private String migrationRecordsPath = "./data/migration-records.json";
    /** 迁移请求记录上限；超出后按 FIFO 淘汰最旧记录。 */
    private int migrationMaxRecords = 10_000;

    public String getMigrationRecordsPath() {
        return migrationRecordsPath;
    }

    public void setMigrationRecordsPath(String migrationRecordsPath) {
        this.migrationRecordsPath = migrationRecordsPath;
    }

    public int getMigrationMaxRecords() {
        return migrationMaxRecords;
    }

    public void setMigrationMaxRecords(int migrationMaxRecords) {
        this.migrationMaxRecords = migrationMaxRecords;
    }

    public String getRootKey() {
        return rootKey;
    }

    public void setRootKey(String rootKey) {
        this.rootKey = rootKey;
    }

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
