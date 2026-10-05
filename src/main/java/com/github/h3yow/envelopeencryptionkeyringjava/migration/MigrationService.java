package com.github.h3yow.envelopeencryptionkeyringjava.migration;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.RewrapService;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.MigrationConflictException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 按请求幂等的迁移服务。
 *
 * <p>语义：调用方每次发起迁移携带自己生成的请求编号（requestId）。
 * <ul>
 *   <li>同一编号 + 相同输入：无论并发同时到达还是服务重启后再次提交，真实迁移只发生一次，
 *       后续一律重放首次结果（密文字节级一致），并以 {@code replayed=true} 标识。</li>
 *   <li>同一编号 + 不同输入：抛出 {@link MigrationConflictException}，
 *       与密文损坏、版本不对等其它失败可区分。</li>
 *   <li>记录有上限，超出后按 FIFO 淘汰最旧记录；被淘汰的编号再次提交时按新请求处理。</li>
 * </ul>
 *
 * <p>恰好一次由“在途请求表”保证：同一编号的并发请求里只有第一个执行真实迁移，
 * 其余等待同一结果并标记为重放。审计日志只记录编号、指纹前缀与判定依据，
 * 不记录密钥材料或密文全文。
 */
public class MigrationService {

    private static final Logger log = LoggerFactory.getLogger(MigrationService.class);

    /** 迁移判定结果：replayed=true 表示本次为重放，未发生真实迁移。 */
    public record MigrationOutcome(String envelope, boolean migrated, boolean replayed) {
    }

    private final RewrapService rewrapService;
    private final MigrationRecordStore store;
    private final ConcurrentHashMap<String, CompletableFuture<MigrationOutcome>> inFlight =
            new ConcurrentHashMap<>();

    public MigrationService(RewrapService rewrapService, MigrationRecordStore store) {
        this.rewrapService = rewrapService;
        this.store = store;
    }

    /** 带请求编号的迁移入口。 */
    public MigrationOutcome migrate(String requestId, String context, String envelope) {
        if (requestId == null || requestId.isBlank()) {
            throw new IllegalArgumentException("requestId must not be blank");
        }
        String fingerprint = fingerprint(context, envelope);
        String fpShort = fingerprint.substring(0, 12);

        // 1. 已完成记录：命中则按指纹判定重放或冲突
        Optional<MigrationRecord> existing = store.find(requestId);
        if (existing.isPresent()) {
            return decideFromRecord(requestId, existing.get(), fingerprint, fpShort);
        }

        // 2. 在途请求：同一编号的并发提交只有第一个真实迁移，其余等待并重放
        CompletableFuture<MigrationOutcome> future = new CompletableFuture<>();
        CompletableFuture<MigrationOutcome> winner = inFlight.putIfAbsent(requestId, future);
        if (winner != null) {
            MigrationOutcome outcome = joinUnwrapped(winner);
            log.info("AUDIT action=migrate requestId={} fingerprint={} decision=replayed"
                    + " reason=concurrent-duplicate", requestId, fpShort);
            return new MigrationOutcome(outcome.envelope(), outcome.migrated(), true);
        }
        try {
            // 双重检查：可能在等待锁期间已有其它线程写入记录
            Optional<MigrationRecord> raced = store.find(requestId);
            if (raced.isPresent()) {
                MigrationOutcome replayed =
                        decideFromRecord(requestId, raced.get(), fingerprint, fpShort);
                future.complete(replayed);
                return replayed;
            }
            RewrapService.RewrapResult result = rewrapService.rewrapWithResult(context, envelope);
            MigrationRecord record = new MigrationRecord();
            record.setRequestId(requestId);
            record.setFingerprintBase64(fingerprint);
            record.setResultEnvelope(result.envelope());
            record.setMigrated(result.migrated());
            record.setCreatedAt(Instant.now());
            store.put(record);
            log.info("AUDIT action=migrate requestId={} fingerprint={} decision=migrated"
                    + " fromVersion={} toVersion={}", requestId, fpShort,
                    result.fromVersion(), result.toVersion());
            MigrationOutcome outcome =
                    new MigrationOutcome(result.envelope(), result.migrated(), false);
            future.complete(outcome);
            return outcome;
        } catch (RuntimeException e) {
            // 失败不记录：同一编号可以修正后重试；在途等待者收到同一失败
            future.completeExceptionally(e);
            throw e;
        } finally {
            inFlight.remove(requestId, future);
        }
    }

    private MigrationOutcome decideFromRecord(String requestId, MigrationRecord record,
                                              String fingerprint, String fpShort) {
        if (!MessageDigest.isEqual(
                record.getFingerprintBase64().getBytes(StandardCharsets.UTF_8),
                fingerprint.getBytes(StandardCharsets.UTF_8))) {
            log.warn("AUDIT action=migrate requestId={} fingerprint={} decision=conflict"
                    + " reason=same-request-id-different-input", requestId, fpShort);
            throw new MigrationConflictException(
                    "requestId " + requestId + " was already used with a different migration input");
        }
        log.info("AUDIT action=migrate requestId={} fingerprint={} decision=replayed"
                + " reason=recorded-result", requestId, fpShort);
        return new MigrationOutcome(record.getResultEnvelope(), record.isMigrated(), true);
    }

    /** 等待在途结果；失败时还原原始异常，保证错误分类与首个请求一致。 */
    private static MigrationOutcome joinUnwrapped(CompletableFuture<MigrationOutcome> future) {
        try {
            return future.join();
        } catch (java.util.concurrent.CompletionException e) {
            if (e.getCause() instanceof RuntimeException cause) {
                throw cause;
            }
            throw e;
        }
    }

    /** 输入指纹：SHA-256(context || 0x00 || envelope)，用于同号不同输入的冲突判定。 */
    static String fingerprint(String context, String envelope) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update((context == null ? "" : context).getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update((envelope == null ? "" : envelope).getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
