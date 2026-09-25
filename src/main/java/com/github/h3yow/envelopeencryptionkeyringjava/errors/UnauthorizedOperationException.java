package com.github.h3yow.envelopeencryptionkeyringjava.errors;

/** 调用方不具备管理权限。 */
public class UnauthorizedOperationException extends CryptoServiceException {
    public UnauthorizedOperationException(String message) {
        super(message);
    }
}
