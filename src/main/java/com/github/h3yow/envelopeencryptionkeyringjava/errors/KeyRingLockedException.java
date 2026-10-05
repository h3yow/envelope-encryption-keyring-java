package com.github.h3yow.envelopeencryptionkeyringjava.errors;

/**
 * 密钥环无法解锁：根口令缺失/错误，或密钥环文件处于受保护格式而未配置根口令。
 *
 * <p>错误信息只描述状态，绝不包含口令或任何密钥材料。
 */
public class KeyRingLockedException extends CryptoServiceException {
    public KeyRingLockedException(String message) {
        super(message);
    }
}
