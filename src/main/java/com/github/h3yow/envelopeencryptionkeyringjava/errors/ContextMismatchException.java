package com.github.h3yow.envelopeencryptionkeyringjava.errors;

/** 解密上下文与加密时约定上下文不一致。 */
public class ContextMismatchException extends CryptoServiceException {
    public ContextMismatchException(String message) {
        super(message);
    }
}
