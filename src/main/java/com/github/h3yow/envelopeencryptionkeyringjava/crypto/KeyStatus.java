package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

/** 主密钥生命周期状态。 */
public enum KeyStatus {
    /** 可用于加密新数据与解密历史数据。 */
    ACTIVE,
    /** 已停用：禁止任何解密/包裹使用，仅保留审计。 */
    DISABLED
}
