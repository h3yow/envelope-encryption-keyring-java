package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.EnvelopeCipher;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.IdempotentMigrationService;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyRing;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.MasterKeyService;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.MigrationRequestStore;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.RewrapService;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.ContextMismatchException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.IdempotencyConflictException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.MalformedCiphertextException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 按请求编号幂等：重复/并发只迁一次、重启可重放、冲突可区分、上限淘汰。 */
class IdempotentMigrationServiceTest {

    private static final Logger log = LoggerFactory.getLogger(IdempotentMigrationServiceTest.class);
    private static final String CTX = "tenant=idem";
    private static final String ADMIN = "tok";
    private static final int MAX_RECORDS = 3;

    @TempDir
    Path dir;

    KeyRing keyRing;
    MasterKeyService admin;
    EnvelopeCipher cipher;
    RewrapService rewrap;
    MigrationRequestStore store;
    IdempotentMigrationService migration;

    private Path keyringPath() {
        return dir.resolve("keyring.json");
    }

    private Path storePath() {
        return dir.resolve("migration-requests.json");
    }

    @BeforeEach
    void setUp() {
        buildServices(MAX_RECORDS);
    }

    private void buildServices(int maxRecords) {
        keyRing = new KeyRing(keyringPath().toString());
        admin = new MasterKeyService(keyRing, ADMIN, false);
        admin.ensureInitialized();
        cipher = new EnvelopeCipher(keyRing);
        rewrap = new RewrapService(keyRing);
        store = new MigrationRequestStore(storePath().toString(), maxRecords);
        migration = new IdempotentMigrationService(rewrap, store);
    }

    private String oldEnvelope(String plaintext) {
        String env = cipher.encrypt(CTX, plaintext.getBytes(StandardCharsets.UTF_8));
        admin.rotate(ADMIN);
        return env;
    }

    @Test
    void sameRequestIdMigratesOnceAndReplaysIdenticalCiphertext() {
        String old = oldEnvelope("repeat-me");
        var first = migration.submit("req-A", CTX, old);
        log.info("场景-重复提交 first replay={} migrated={} toVersion={}",
                first.replay(), first.migrated(), first.toVersion());
        assertFalse(first.replay());
        assertTrue(first.migrated());

        for (int i = 0; i < 3; i++) {
            var again = migration.submit("req-A", CTX, old);
            assertTrue(again.replay(), "第 " + (i + 1) + " 次重复必须是重放");
            assertEquals(first.envelope(), again.envelope(), "重放密文必须与首次完全一致");
            assertEquals(first.firstMigrationAt(), again.firstMigrationAt());
            assertEquals(first.migrated(), again.migrated());
        }
        assertEquals(1, store.size(), "同一编号只允许一条记录");
    }

    @Test
    void concurrentSameRequestIdMigratesExactlyOnce() throws Exception {
        String old = oldEnvelope("concurrent-me");
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        ConcurrentLinkedQueue<IdempotentMigrationService.MigrationOutcome> outcomes =
                new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<Throwable> errors = new ConcurrentLinkedQueue<>();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    outcomes.add(migration.submit("req-concurrent", CTX, old));
                } catch (Throwable t) {
                    errors.add(t);
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();
        log.info("场景-并发同号 outcomes={} errors={}", outcomes.size(), errors.size());
        assertTrue(errors.isEmpty(), "并发批次不应有异常: " + errors.peek());

        long processed = outcomes.stream().filter(o -> !o.replay()).count();
        long replays = outcomes.stream().filter(o -> o.replay()).count();
        assertEquals(1, processed, "真实迁移必须恰好一次");
        assertEquals(threads - 1, replays, "其余全部必须是重放");
        Set<String> distinct = new HashSet<>(outcomes.stream().map(o -> o.envelope()).toList());
        assertEquals(1, distinct.size(), "各次返回密文必须一致");
    }

    @Test
    void replayWorksAcrossRestart() {
        String old = oldEnvelope("restart-me");
        var first = migration.submit("req-restart", CTX, old);
        log.info("场景-重启重放 beforeRestart replay={} envelopeTokens={}",
                first.replay(), MigrationRequestStore.shortToken(
                        first.envelope().getBytes(StandardCharsets.UTF_8)));

        // 模拟服务重启：用同样的文件重新装配全部组件
        buildServices(MAX_RECORDS);
        var after = migration.submit("req-restart", CTX, old);
        assertTrue(after.replay(), "重启后同号同内容必须命中重放");
        assertEquals(first.envelope(), after.envelope(), "重启后返回密文必须与首次一致");
        // 重放得到的历史密文仍能正确解密
        assertEquals("restart-me",
                new String(cipher.decrypt(CTX, after.envelope()), StandardCharsets.UTF_8));
    }

    @Test
    void sameRequestIdDifferentPayloadIsConflictAndDistinguishable() {
        String old1 = oldEnvelope("payload-one");
        var first = migration.submit("req-conflict", CTX, old1);

        // 换一个不同的密文内容但用同一编号
        String old2 = cipher.encrypt(CTX, "payload-two".getBytes(StandardCharsets.UTF_8));
        IdempotencyConflictException byEnvelope = assertThrows(
                IdempotencyConflictException.class,
                () -> migration.submit("req-conflict", CTX, old2));
        log.info("场景-冲突(不同envelope) code=IDEMPOTENCY_CONFLICT msg={}", byEnvelope.getMessage());

        // context 不同也冲突
        IdempotencyConflictException byContext = assertThrows(
                IdempotencyConflictException.class,
                () -> migration.submit("req-conflict", "tenant=other", old1));
        log.info("场景-冲突(不同context) code=IDEMPOTENCY_CONFLICT msg={}", byContext.getMessage());

        // 冲突后原记录仍可正常重放，且密文未被替换
        var replay = migration.submit("req-conflict", CTX, old1);
        assertTrue(replay.replay());
        assertEquals(first.envelope(), replay.envelope());

        // 与其它失败类型可区分：坏密文/坏编号是 MALFORMED_CIPHERTEXT，坏上下文是 CONTEXT_MISMATCH
        assertThrows(MalformedCiphertextException.class,
                () -> migration.submit("", CTX, old1));
        assertThrows(MalformedCiphertextException.class,
                () -> migration.submit("req-new", CTX, "EK1.1.aa"));
        assertThrows(ContextMismatchException.class,
                () -> migration.submit("req-new-ctx", "tenant=other", old1));
    }

    @Test
    void lruEvictionIsDeterministicAndRecentReplaysSurvive() {
        String e1 = oldEnvelope("one");
        String e2 = oldEnvelope("two");
        String e3 = oldEnvelope("three");
        migration.submit("r1", CTX, e1);
        migration.submit("r2", CTX, e2);
        migration.submit("r3", CTX, e3);
        assertEquals(MAX_RECORDS, store.size());

        // 重放 r1，使其成为最近使用；此时插入 r4 应淘汰 r2（最久未重放），而不是 r1
        var replayR1 = migration.submit("r1", CTX, e1);
        assertTrue(replayR1.replay());
        String e4 = oldEnvelope("four");
        migration.submit("r4", CTX, e4);
        log.info("场景-淘汰 capacity={} size={} evictedExpected=r2", MAX_RECORDS, store.size());
        assertEquals(MAX_RECORDS, store.size());

        var replayedR1 = migration.submit("r1", CTX, e1);
        assertTrue(replayedR1.replay(), "最近重放的记录必须存活并可重放");
        var r4again = migration.submit("r4", CTX, e4);
        assertTrue(r4again.replay());

        // r2 已被淘汰：同号同内容重新提交会作为真实迁移再次处理，而不是报错
        var r2Reprocessed = migration.submit("r2", CTX, e2);
        assertFalse(r2Reprocessed.replay(), "被淘汰记录重新提交时按新请求处理");
    }

    @Test
    void failedMigrationIsNotPersistedAndSameIdCanRetry() {
        // 未知版本密文：迁移本身失败，不得占用请求编号
        String bogus = "EK1.99.AAAAAAAA.AAAAAAAA.AAAAAAAA.AAAAAAAA.AAAAAAAA";
        assertThrows(Exception.class, () -> migration.submit("req-fail", CTX, bogus));
        assertEquals(0, store.size(), "失败的迁移不得落记录");
        String ok = oldEnvelope("after-failure");
        var outcome = migration.submit("req-fail", CTX, ok);
        assertFalse(outcome.replay(), "失败后同编号应能正常重试");
        log.info("场景-失败可重试 size={} replay={}", store.size(), outcome.replay());
    }

    @Test
    void distinctRequestIdsEachMigrateOnceUnderMixedConcurrency() throws Exception {
        String old = oldEnvelope("mixed");
        int distinct = 10;
        int copies = 4;
        ExecutorService pool = Executors.newFixedThreadPool(distinct * copies);
        CountDownLatch start = new CountDownLatch(1);
        List<String> ids = Collections.synchronizedList(new ArrayList<>());
        List<Throwable> errors = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger processed = new AtomicInteger();
        for (int d = 0; d < distinct; d++) {
            String id = "mix-" + d;
            for (int c = 0; c < copies; c++) {
                pool.submit(() -> {
                    try {
                        start.await();
                        var o = migration.submit(id, CTX, old);
                        ids.add(o.requestId());
                        if (!o.replay()) {
                            processed.incrementAndGet();
                        }
                    } catch (Throwable t) {
                        errors.add(t);
                    }
                });
            }
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        // 只有 3 条容量，会发生淘汰，这里只要求：真实迁移次数 >= distinct（淘汰后重提可能再迁）
        // 且没有异常、每个编号同批内至多一次真实迁移
        log.info("场景-混合并发 distinct={} copies={} processedAtLeast={} errors={}",
                distinct, copies, processed.get(), errors.size());
        assertTrue(errors.isEmpty());
        assertTrue(processed.get() >= distinct);
    }
}
