package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

import com.github.h3yow.envelopeencryptionkeyringjava.errors.IdempotencyConflictException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.MalformedCiphertextException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 按请求编号幂等的迁移服务：在 {@link RewrapService} 之上保证
 * “同一编号 + 同一内容”的迁移在任意并发与重启重放下真实迁移恰好发生一次，
 * 之后每次返回与第一次完全一致的密文并明确标记为重放。
 *
 * <p>同一编号但内容不同（context 或 envelope 变化）时以
 * {@link IdempotencyConflictException} 明确拒绝，与密文损坏、版本错误等失败区分。
 *
 * <p>判定依据全部落审计日志；日志只出现请求编号、指纹前缀与版本号，
 * 不出现密钥材料或密文全文。
 */
public class IdempotentMigrationService {

    private static final Logger log = LoggerFactory.getLogger(IdempotentMigrationService.class);

    /** 迁移判定结果。 */
    public record MigrationOutcome(
            String requestId,
            String envelope,
            boolean migrated,
            boolean replay,
            int fromVersion,
            int toVersion,
            long firstMigrationAt) {
    }

    private final RewrapService rewrapService;
    private final MigrationRequestStore store;
    /** 每个请求编号一把锁，保证同编号并发请求在 JVM 内串行判定。 */
    private final ConcurrentHashMap<String, Object> requestLocks = new ConcurrentHashMap<>();

    public IdempotentMigrationService(RewrapService rewrapService, MigrationRequestStore store) {
        this.rewrapService = rewrapService;
        this.store = store;
    }

    public MigrationOutcome submit(String requestId, String context, String encodedEnvelope) {
        if (requestId == null || requestId.isBlank()) {
            throw new MalformedCiphertextException("requestId must not be empty");
        }
        if (context == null || encodedEnvelope == null || encodedEnvelope.isBlank()) {
            throw new MalformedCiphertextException("context and envelope must not be empty");
        }
        String fingerprint = fingerprint(context, encodedEnvelope);

        // 快路径：已存在记录时直接判定重放或冲突（访问序由 store 刷新）
        MigrationRequestStore.Entry existing = store.find(requestId);
        if (existing != null) {
            return resolveExisting(requestId, fingerprint, existing);
        }

        Object lock = requestLocks.computeIfAbsent(requestId, k -> new Object());
        try {
            synchronized (lock) {
                // 双检：并发批次中只有第一个线程进入真实迁移
                existing = store.find(requestId);
                if (existing != null) {
                    return resolveExisting(requestId, fingerprint, existing);
                }
                // 真实迁移；迁移失败（版本/篡改/上下文等）不落记录，允许调用方修正后同号重试
                RewrapService.RewrapResult result =
                        rewrapService.rewrapWithResult(context, encodedEnvelope);
                MigrationRequestStore.Entry entry = new MigrationRequestStore.Entry();
                entry.requestId = requestId;
                entry.fingerprint = fingerprint;
                entry.envelope = result.envelope();
                entry.migrated = result.migrated();
                entry.fromVersion = result.fromVersion();
                entry.toVersion = result.toVersion();
                entry.createdAt = System.currentTimeMillis();
                store.insert(entry);
                log.info("AUDIT action=idempotent-migration requestId={} fingerprint={} decision=processed"
                                + " migrated={} fromVersion={} toVersion={}",
                        requestId, MigrationRequestStore.prefix(fingerprint),
                        result.migrated(), result.fromVersion(), result.toVersion());
                return new MigrationOutcome(requestId, result.envelope(), result.migrated(),
                        false, result.fromVersion(), result.toVersion(), entry.createdAt);
            }
        } finally {
            requestLocks.remove(requestId, lock);
        }
    }

    private MigrationOutcome resolveExisting(String requestId, String fingerprint,
                                             MigrationRequestStore.Entry existing) {
        if (!constantTimeEquals(fingerprint, existing.fingerprint)) {
            log.warn("AUDIT action=idempotent-migration requestId={} fingerprint={} decision=conflict"
                            + " storedFingerprint={}",
                    requestId, MigrationRequestStore.prefix(fingerprint),
                    MigrationRequestStore.prefix(existing.fingerprint));
            throw new IdempotencyConflictException(
                    "requestId was already used with a different payload; use a new requestId");
        }
        log.info("AUDIT action=idempotent-migration requestId={} fingerprint={} decision=replay"
                        + " migratedOriginally={} fromVersion={} toVersion={}",
                requestId, MigrationRequestStore.prefix(fingerprint),
                existing.migrated, existing.fromVersion, existing.toVersion);
        return new MigrationOutcome(requestId, existing.envelope, existing.migrated,
                true, existing.fromVersion, existing.toVersion, existing.createdAt);
    }

    /** 请求内容指纹：context 与 envelope 的规范化哈希，日志中只取前缀。 */
    static String fingerprint(String context, String envelope) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] c = context.getBytes(StandardCharsets.UTF_8);
            byte[] e = envelope.getBytes(StandardCharsets.UTF_8);
            md.update("ctx|".getBytes(StandardCharsets.UTF_8));
            md.update(encodeLength(c.length));
            md.update(c);
            md.update("env|".getBytes(StandardCharsets.UTF_8));
            md.update(encodeLength(e.length));
            md.update(e);
            return HexFormat.of().formatHex(md.digest());
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    private static byte[] encodeLength(int len) {
        return Integer.toString(len).getBytes(StandardCharsets.UTF_8);
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
