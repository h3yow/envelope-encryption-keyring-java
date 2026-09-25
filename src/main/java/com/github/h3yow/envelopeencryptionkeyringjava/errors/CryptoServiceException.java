package com.github.h3yow.envelopeencryptionkeyringjava.errors;

/** 对外暴露的受检异常基类；底层密码学异常不得原样透出。 */
public abstract class CryptoServiceException extends RuntimeException {
    protected CryptoServiceException(String message) {
        super(message);
    }
}
