package com.github.h3yow.envelopeencryptionkeyringjava.auth;

/** 鉴权/授权失败。消息不得包含任何密钥材料。 */
public class AccessDeniedException extends RuntimeException {
    public AccessDeniedException(String message) {
        super(message);
    }
}
