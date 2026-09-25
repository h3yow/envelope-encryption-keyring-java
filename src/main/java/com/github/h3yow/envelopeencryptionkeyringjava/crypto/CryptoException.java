package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

/** 业务级密码学异常，只携带可对外暴露的错误码与安全消息。 */
public class CryptoException extends RuntimeException {
    private final ErrorCode errorCode;

    public CryptoException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public CryptoException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }
}
