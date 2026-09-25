package com.github.h3yow.envelopeencryptionkeyringjava.keyring;

import java.util.List;

/**
 * 密钥环完整持久化状态。
 *
 * @param kdfSalt        PBKDF2 盐（首次初始化生成）
 * @param versionCounter 版本号单调计数器
 * @param currentVersion 当前加密默认版本
 * @param keys           全部主密钥版本记录（新的在前）
 */
public record KeyRingState(
        byte[] kdfSalt,
        long versionCounter,
        String currentVersion,
        List<MasterKeyRecord> keys) {

    public static KeyRingState empty() {
        return new KeyRingState(new byte[0], 0L, null, List.of());
    }
}
