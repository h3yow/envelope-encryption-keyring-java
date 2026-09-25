package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

import java.time.Instant;

/** 主密钥（KEK）实体，材料以 Base64 形式持久化。 */
public class MasterKey {
    private int version;
    private KeyStatus status;
    private String materialBase64;
    private Instant createdAt;

    public MasterKey() {
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public KeyStatus getStatus() {
        return status;
    }

    public void setStatus(KeyStatus status) {
        this.status = status;
    }

    public String getMaterialBase64() {
        return materialBase64;
    }

    public void setMaterialBase64(String materialBase64) {
        this.materialBase64 = materialBase64;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
