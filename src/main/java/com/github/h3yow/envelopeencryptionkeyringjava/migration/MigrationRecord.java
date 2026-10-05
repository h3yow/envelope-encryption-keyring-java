package com.github.h3yow.envelopeencryptionkeyringjava.migration;

import java.time.Instant;

/** 一条已完成的迁移请求记录：请求编号、输入指纹、迁移结果与首次完成时间。 */
public class MigrationRecord {
    private String requestId;
    private String fingerprintBase64;
    private String resultEnvelope;
    private boolean migrated;
    private Instant createdAt;

    public MigrationRecord() {
    }

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public String getFingerprintBase64() {
        return fingerprintBase64;
    }

    public void setFingerprintBase64(String fingerprintBase64) {
        this.fingerprintBase64 = fingerprintBase64;
    }

    public String getResultEnvelope() {
        return resultEnvelope;
    }

    public void setResultEnvelope(String resultEnvelope) {
        this.resultEnvelope = resultEnvelope;
    }

    public boolean isMigrated() {
        return migrated;
    }

    public void setMigrated(boolean migrated) {
        this.migrated = migrated;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
