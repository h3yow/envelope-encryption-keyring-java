package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

/** 对外可区分的错误码。底层密码学异常不得透出，统一映射到这里。 */
public enum ErrorCode {
    UNAUTHORIZED,
    KEY_VERSION_UNKNOWN,
    KEY_VERSION_DISABLED,
    CIPHERTEXT_MALFORMED,
    CONTEXT_MISMATCH,
    CIPHERTEXT_TAMPERED,
    IDEMPOTENCY_CONFLICT,
    NO_ACTIVE_KEY,
    INVALID_REQUEST,
    INTERNAL_ERROR
}
