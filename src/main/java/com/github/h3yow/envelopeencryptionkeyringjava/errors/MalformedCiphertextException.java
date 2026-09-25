package com.github.h3yow.envelopeencryptionkeyringjava.errors;

/** 密文结构不完整或版本线索缺失。 */
public class MalformedCiphertextException extends CryptoServiceException {
    public MalformedCiphertextException(String message) {
        super(message);
    }
}
