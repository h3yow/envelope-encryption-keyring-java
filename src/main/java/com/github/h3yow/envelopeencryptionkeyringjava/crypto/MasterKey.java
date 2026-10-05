package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

/**
 * 主密钥（KEK）实体。
 *
 * <p>明文材料只存在于内存：{@code materialBase64} 标记为 WRITE_ONLY，
 * 仅用于读取旧格式（v1）密钥环文件，永不序列化落盘；新格式（v2）落盘的是
 * 根密钥包裹后的 {@code wrappedMaterialBase64} 与 {@code wrapIvBase64}。
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class MasterKey {
    private int version;
    private KeyStatus status;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String materialBase64;
    private String wrappedMaterialBase64;
    private String wrapIvBase64;
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

    public String getWrappedMaterialBase64() {
        return wrappedMaterialBase64;
    }

    public void setWrappedMaterialBase64(String wrappedMaterialBase64) {
        this.wrappedMaterialBase64 = wrappedMaterialBase64;
    }

    public String getWrapIvBase64() {
        return wrapIvBase64;
    }

    public void setWrapIvBase64(String wrapIvBase64) {
        this.wrapIvBase64 = wrapIvBase64;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
