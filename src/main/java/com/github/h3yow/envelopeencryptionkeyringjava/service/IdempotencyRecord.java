package com.github.h3yow.envelopeencryptionkeyringjava.service;

/**
 * 重包裹幂等记录。
 *
 * @param requestId        请求标识
 * @param inputDigest      输入密文（连同上下文）的摘要，用于区分同 requestId 的不同请求
 * @param outputCiphertext 首次成功迁移的输出密文
 * @param outputVersion    输出密文所用主密钥版本
 * @param createdAt        创建时间戳
 */
public record IdempotencyRecord(
        String requestId,
        String inputDigest,
        String outputCiphertext,
        String outputVersion,
        long createdAt) {
}
