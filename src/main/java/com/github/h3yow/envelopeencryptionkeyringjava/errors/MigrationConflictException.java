package com.github.h3yow.envelopeencryptionkeyringjava.errors;

/** 同一迁移请求编号携带了与首次提交不同的输入时抛出，与其它迁移失败可区分。 */
public class MigrationConflictException extends CryptoServiceException {
    public MigrationConflictException(String message) {
        super(message);
    }
}
