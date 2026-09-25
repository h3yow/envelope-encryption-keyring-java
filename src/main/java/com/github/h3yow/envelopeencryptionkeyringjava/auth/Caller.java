package com.github.h3yow.envelopeencryptionkeyringjava.auth;

/**
 * 已认证调用方。
 *
 * @param role 角色
 * @param name 调用方标识，仅用于审计
 */
public record Caller(CallerRole role, String name) {
}
