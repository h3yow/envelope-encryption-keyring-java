package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.EnvelopeCipher;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyRing;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyRingProtection;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.MasterKeyService;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.RewrapService;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.CiphertextIntegrityException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.MigrationConflictException;
import com.github.h3yow.envelopeencryptionkeyringjava.migration.MigrationRecordStore;
import com.github.h3yow.envelopeencryptionkeyringjava.migration.MigrationService;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 按请求幂等迁移：同号只迁一次、并发恰好一次、重启可重放、同号不同输入冲突、记录上限淘汰。 */
class MigrationIdempotencyTest {

    private static final Logger log = LoggerFactory.getLogger(MigrationIdempotencyTest.class);
    private static final String CTX = "tenant=idem";
    private static final String ADMIN = "tok";
    private static final int MAX_RECORDS = 100;

    @TempDir
    Path dir;

    KeyRing keyRing;
    MasterKeyService admin;
    EnvelopeCipher cipher;
    RewrapService rewrap;
    MigrationService migration;
    String recordsPath;

    @BeforeEach
    void setUp() {
        keyRing = new KeyRing(dir.resolve("keyring.json").toString(),
                KeyRingProtection.fromRootKey("test-root-key"));
        admin = new MasterKeyService(keyRing, ADMIN, false);
        admin.ensureInitialized();
        cipher = new EnvelopeCipher(keyRing);
        rewrap = new RewrapService(keyRing);
        recordsPath = dir.resolve("migration-records.json").toString();
        migration = new MigrationService(rewrap, new MigrationRecordStore(recordsPath, MAX_RECORDS));
    }

    /** 造一条旧版本密文：先加密再轮换，使其需要真实迁移。 */
    private String staleEnvelope(String plaintext) {
        String env = cipher.encrypt(CTX, plaintext.getBytes(StandardCharsets.UTF_8));
        admin.rotate(ADMIN);
        return env;
    }

    @Test
    void sameRequestIdMigratesOnceThenReplays() {
        String old = staleEnvelope("replay-me");
        var first = migration.migrate("req-1", CTX, old);
        var second = migration.migrate("req-1", CTX, old);
        var third = migration.migrate("req-1", CTX, old);
        log.info("repeatSubmit first(migrated={},replayed={}) second(replayed={}) third(replayed={})"
                + " identical={}", first.migrated(), first.replayed(), second.replayed(),
                third.replayed(),
                first.envelope().equals(second.envelope())
                        && second.envelope().equals(third.envelope()));
        assertTrue(first.migrated());
        assertFalse(first.replayed());
        assertTrue(second.replayed(), "重复提交必须标识为重放");
        assertTrue(third.replayed());
        assertEquals(first.envelope(), second.envelope(), "重放必须返回与首次一模一样的密文");
        assertEquals(first.envelope(), third.envelope());
    }

    @Test
    void concurrentDuplicatesMigrateExactlyOnce() throws Exception {
        String old = staleEnvelope("burst");
        int threads = 16;
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<MigrationService.MigrationOutcome> outcomes =
                new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<Throwable> errors = new ConcurrentLinkedQueue<>();
        Thread[] workers = new Thread[threads];
        for (int i = 0; i < threads; i++) {
            workers[i] = new Thread(() -> {
                try {
                    start.await();
                    outcomes.add(migration.migrate("req-burst", CTX, old));
                } catch (Throwable t) {
                    errors.add(t);
                }
            }, "dup-" + i);
        }
        for (Thread t : workers) {
            t.start();
        }
        start.countDown();
        for (Thread t : workers) {
            t.join(TimeUnit.SECONDS.toMillis(30));
        }
        AtomicInteger realMigrations = new AtomicInteger();
        AtomicInteger replays = new AtomicInteger();
        outcomes.forEach(o -> {
            if (o.replayed()) {
                replays.incrementAndGet();
            } else {
                realMigrations.incrementAndGet();
            }
        });
        String firstEnvelope = outcomes.peek().envelope();
        boolean allIdentical = outcomes.stream().allMatch(o -> o.envelope().equals(firstEnvelope));
        log.info("concurrentBurst threads={} realMigrations={} replays={} allIdentical={} errors={}",
                threads, realMigrations.get(), replays.get(), allIdentical, errors.size());
        assertTrue(errors.isEmpty(), "并发重复提交不得出错: "
                + (errors.isEmpty() ? "" : errors.peek()));
        assertEquals(1, realMigrations.get(), "真实迁移必须恰好发生一次");
        assertEquals(threads - 1, replays.get(), "其余必须全部为重放");
        assertTrue(allIdentical, "各次返回的密文必须一致");
    }

    @Test
    void replaySurvivesRestart() {
        String old = staleEnvelope("durable");
        var first = migration.migrate("req-restart", CTX, old);
        assertFalse(first.replayed());

        // 模拟重启：全新 MigrationService + 从同一文件加载的 RecordStore（密钥环也重新加载）
        KeyRing keyRing2 = new KeyRing(dir.resolve("keyring.json").toString(),
                KeyRingProtection.fromRootKey("test-root-key"));
        MigrationService migration2 = new MigrationService(new RewrapService(keyRing2),
                new MigrationRecordStore(recordsPath, MAX_RECORDS));
        var afterRestart = migration2.migrate("req-restart", CTX, old);
        log.info("restartReplay firstMigrated={} afterRestart(replayed={}) identical={}",
                first.migrated(), afterRestart.replayed(),
                first.envelope().equals(afterRestart.envelope()));
        assertTrue(afterRestart.replayed(), "重启后同号同输入必须重放而非再迁");
        assertEquals(first.envelope(), afterRestart.envelope());
    }

    @Test
    void sameRequestIdWithDifferentInputRejectedAsConflict() {
        String old1 = staleEnvelope("input-a");
        String old2 = cipher.encrypt(CTX, "input-b".getBytes(StandardCharsets.UTF_8));
        migration.migrate("req-conflict", CTX, old1);

        MigrationConflictException conflict = assertThrows(MigrationConflictException.class,
                () -> migration.migrate("req-conflict", CTX, old2));
        log.info("conflictReject exception={} message={}",
                conflict.getClass().getSimpleName(), conflict.getMessage());
        // 冲突必须能与密文损坏等其它失败区分
        assertNotEquals(CiphertextIntegrityException.class, conflict.getClass());
        assertTrue(conflict instanceof com.github.h3yow.envelopeencryptionkeyringjava
                .errors.CryptoServiceException);
        // 不同上下文也算不同输入
        assertThrows(MigrationConflictException.class,
                () -> migration.migrate("req-conflict", "tenant=other", old1));
        // 冲突拒绝后，原始输入仍能正常重放
        var replay = migration.migrate("req-conflict", CTX, old1);
        assertTrue(replay.replayed());
    }

    @Test
    void corruptedEnvelopeFailureIsNotRecordedAsConflict() {
        String old = staleEnvelope("tamper");
        // 篡改 wrappedDek 段 → 解包完整性失败，与冲突是不同错误
        String[] parts = old.split("\\.", -1);
        char[] dek = parts[3].toCharArray();
        dek[0] = dek[0] == 'A' ? 'B' : 'A';
        parts[3] = new String(dek);
        String tampered = String.join(".", parts);
        assertThrows(CiphertextIntegrityException.class,
                () -> migration.migrate("req-tamper", CTX, tampered));
        log.info("tamperRejected expectation=CiphertextIntegrityException (distinct from conflict)");
        // 失败不记录：同一编号修正输入后可正常迁移
        var ok = migration.migrate("req-tamper", CTX, old);
        assertTrue(ok.migrated());
        assertFalse(ok.replayed());
    }

    @Test
    void recordCapEvictsOldestAndRecentStillReplay() {
        int cap = 3;
        MigrationService bounded = new MigrationService(rewrap,
                new MigrationRecordStore(dir.resolve("bounded-records.json").toString(), cap));
        String[] envs = new String[5];
        for (int i = 0; i < 5; i++) {
            envs[i] = cipher.encrypt(CTX, ("rec-" + i).getBytes(StandardCharsets.UTF_8));
        }
        admin.rotate(ADMIN);
        MigrationService.MigrationOutcome[] firsts = new MigrationService.MigrationOutcome[5];
        for (int i = 0; i < 5; i++) {
            firsts[i] = bounded.migrate("req-cap-" + i, CTX, envs[i]);
            assertFalse(firsts[i].replayed());
        }
        // cap=3，req-cap-0 与 req-cap-1 已被淘汰；最近三条仍可重放
        var recent = bounded.migrate("req-cap-4", CTX, envs[4]);
        var recent2 = bounded.migrate("req-cap-3", CTX, envs[3]);
        log.info("recordCap cap={} recentReplayed={} recent2Replayed={}",
                cap, recent.replayed(), recent2.replayed());
        assertTrue(recent.replayed(), "淘汰后最近提交过的请求必须仍能重放");
        assertTrue(recent2.replayed());
        assertEquals(firsts[4].envelope(), recent.envelope());
        // 已淘汰的编号再次提交：按新请求处理（重新迁移，不是冲突也不是重放）
        var evicted = bounded.migrate("req-cap-0", CTX, envs[0]);
        log.info("evictedResubmit replayed={} migrated={}", evicted.replayed(), evicted.migrated());
        assertFalse(evicted.replayed(), "被淘汰的编号按新请求处理");
    }

    @Test
    void blankRequestIdRejected() {
        String old = staleEnvelope("no-id");
        log.info("blankRequestId expectation=IllegalArgumentException");
        assertThrows(IllegalArgumentException.class, () -> migration.migrate("", CTX, old));
        assertThrows(IllegalArgumentException.class, () -> migration.migrate(null, CTX, old));
        assertThrows(IllegalArgumentException.class, () -> migration.migrate("   ", CTX, old));
    }

    @Test
    void recordStorePersistsAcrossReload() {
        String old = staleEnvelope("persist");
        migration.migrate("req-persist", CTX, old);
        MigrationRecordStore reloaded = new MigrationRecordStore(recordsPath, MAX_RECORDS);
        log.info("storeReload size={}", reloaded.size());
        assertEquals(1, reloaded.size());
        assertTrue(reloaded.find("req-persist").isPresent());
    }

    @Test
    void manyDistinctRequestsEachMigrateOnce() {
        String old = staleEnvelope("shared-source");
        // 同一输入密文、不同请求编号：各自都是独立请求，各自真实迁移一次
        var a = migration.migrate("req-distinct-a", CTX, old);
        var b = migration.migrate("req-distinct-b", CTX, old);
        log.info("distinctIds a(replayed={}) b(replayed={})", a.replayed(), b.replayed());
        assertFalse(a.replayed());
        assertFalse(b.replayed());
        // 重放各自一致
        assertEquals(a.envelope(), migration.migrate("req-distinct-a", CTX, old).envelope());
        assertEquals(b.envelope(), migration.migrate("req-distinct-b", CTX, old).envelope());
        assertEquals(List.of(true, true),
                List.of(migration.migrate("req-distinct-a", CTX, old).replayed(),
                        migration.migrate("req-distinct-b", CTX, old).replayed()));
    }
}
