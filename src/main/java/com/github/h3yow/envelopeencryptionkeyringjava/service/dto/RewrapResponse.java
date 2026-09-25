package com.github.h3yow.envelopeencryptionkeyringjava.service.dto;

public record RewrapResponse(String ciphertext, String keyVersion, boolean replayed) {
}
