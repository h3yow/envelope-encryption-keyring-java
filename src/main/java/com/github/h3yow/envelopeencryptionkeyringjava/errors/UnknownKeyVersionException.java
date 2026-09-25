package com.github.h3yow.envelopeencryptionkeyringjava.errors;

/** 密文引用了未知的密钥版本。 */
public class UnknownKeyVersionException extends CryptoServiceException {
    public UnknownKeyVersionException(String message) {
        super(message);
    }
}
