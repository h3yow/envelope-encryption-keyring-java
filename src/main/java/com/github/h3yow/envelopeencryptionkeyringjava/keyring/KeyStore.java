package com.github.h3yow.envelopeencryptionkeyringjava.keyring;

/** 密钥环持久化抽象。 */
public interface KeyStore {

    /**
     * 加载持久化状态；文件不存在时返回 null（首次启动）。
     * 文件存在但无法解析时抛 INTERNAL_ERROR，绝不静默重建导致历史数据不可解密。
     */
    KeyRingState load();

    /** 原子写入完整状态（临时文件 + move）。 */
    void save(KeyRingState state);
}
