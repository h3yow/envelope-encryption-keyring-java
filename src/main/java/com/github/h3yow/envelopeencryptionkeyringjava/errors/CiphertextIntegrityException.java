package com.github.h3yow.envelopeencryptionkeyringjava.errors;

/** 密文被篡改或认证失败（含上下文不匹配导致的 GCM 校验失败之外的结构性判定）。 */
public class CiphertextIntegrityException extends CryptoServiceException {
    public CiphertextIntegrityException(String message) {
        super(message);
    }
}
