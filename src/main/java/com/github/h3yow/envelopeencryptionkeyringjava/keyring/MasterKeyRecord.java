package com.github.h3yow.envelopeencryptionkeyringjava.keyring;

/**
 * 主密钥版本记录：密钥材料不以明文落盘，只保存经根密钥包裹后的密文。
 *
 * @param version    版本标识，单调递增
 * @param status     启停状态
 * @param wrappedKey 经根密钥 AES-GCM 包裹后的主密钥材料
 * @param wrapIv     包裹所用 IV
 * @param createdAt  创建时间戳
 * @param current    是否为当前加密默认版本
 */
public record MasterKeyRecord(
        String version,
        KeyStatus status,
        byte[] wrappedKey,
        byte[] wrapIv,
        long createdAt,
        boolean current) {
}
