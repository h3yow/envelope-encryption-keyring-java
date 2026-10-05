package com.github.h3yow.envelopeencryptionkeyringjava.errors;

/**
 * 同一请求编号（requestId）对应的请求内容与首次提交不一致。
 *
 * <p>与密文损坏、版本不对等失败明确区分：调用方应更换请求编号后重试。
 */
public class IdempotencyConflictException extends CryptoServiceException {
    public IdempotencyConflictException(String message) {
        super(message);
    }
}
