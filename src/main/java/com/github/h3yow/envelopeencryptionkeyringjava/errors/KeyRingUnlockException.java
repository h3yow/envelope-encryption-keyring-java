package com.github.h3yow.envelopeencryptionkeyringjava.errors;

/** 根口令缺失/错误或密钥环落盘数据无法解开时抛出；消息中不得包含密钥材料或口令。 */
public class KeyRingUnlockException extends CryptoServiceException {
    public KeyRingUnlockException(String message) {
        super(message);
    }
}
