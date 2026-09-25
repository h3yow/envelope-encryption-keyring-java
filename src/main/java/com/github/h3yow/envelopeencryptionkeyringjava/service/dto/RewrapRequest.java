package com.github.h3yow.envelopeencryptionkeyringjava.service.dto;

public record RewrapRequest(String ciphertext, String context, String requestId) {
}
