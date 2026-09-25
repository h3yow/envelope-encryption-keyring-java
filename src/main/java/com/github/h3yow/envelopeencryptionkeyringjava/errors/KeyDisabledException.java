package com.github.h3yow.envelopeencryptionkeyringjava.errors;

/** 目标密钥版本已停用。 */
public class KeyDisabledException extends CryptoServiceException {
    public KeyDisabledException(String message) {
        super(message);
    }
}
