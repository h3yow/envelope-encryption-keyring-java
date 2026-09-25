package com.github.h3yow.envelopeencryptionkeyringjava.service.dto;

public record KeyView(String version, String status, boolean current, long createdAt) {
}
