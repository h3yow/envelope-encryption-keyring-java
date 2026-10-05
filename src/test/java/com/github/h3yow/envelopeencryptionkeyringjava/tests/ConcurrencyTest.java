package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CiphertextEnvelope;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.EnvelopeCipher;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyRing;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyRingProtection;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.MasterKeyService;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.RewrapService;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReferenceArray;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 并发轮换、重包裹与解密：不得出现半迁移状态、重复处理或不可解释结果。 */
class ConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrencyTest.class);
    private static final String CTX = "tenant=concurrent";
    private static final String ADMIN = "tok";
    private static final int RECORDS = 8;
    private static final int ROTATIONS = 5;

    @TempDir
    Path dir;

    KeyRing keyRing;
    MasterKeyService admin;
    EnvelopeCipher cipher;
    RewrapService rewrap;

    @BeforeEach
    void setUp() {
        keyRing = new KeyRing(dir.resolve("keyring.json").toString(), KeyRingProtection.fromRootKey("test-root-key"));
        admin = new MasterKeyService(keyRing, ADMIN, false);
        admin.ensureInitialized();
        cipher = new EnvelopeCipher(keyRing);
        rewrap = new RewrapService(keyRing);
    }

    @Test
    void concurrentRotationRewrapAndDecryptStayConsistent() throws Exception {
        byte[][] plaintexts = new byte[RECORDS][];
        AtomicReferenceArray<String> envelopes = new AtomicReferenceArray<>(RECORDS);
        for (int i = 0; i < RECORDS; i++) {
            plaintexts[i] = ("record-" + i).getBytes(StandardCharsets.UTF_8);
            envelopes.set(i, cipher.encrypt(CTX, plaintexts[i]));
        }
        int initialVersion = keyRing.activeKey().orElseThrow().getVersion();
        log.info("concurrency start records={} initialVersion={}", RECORDS, initialVersion);

        ConcurrentLinkedQueue<Throwable> unexpected = new ConcurrentLinkedQueue<>();
        AtomicInteger rewrapMigrations = new AtomicInteger();
        AtomicInteger decryptSuccesses = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);
        Thread[] threads = new Thread[RECORDS * 2 + 1];

        // 轮换线程：有序轮换若干次
        threads[0] = new Thread(() -> {
            await(start);
            for (int r = 0; r < ROTATIONS; r++) {
                try {
                    admin.rotate(ADMIN);
                    Thread.sleep(5);
                } catch (Throwable t) {
                    unexpected.add(t);
                }
            }
        }, "rotator");

        // 重包裹线程：反复将本记录迁移到当前版本（幂等）
        for (int i = 0; i < RECORDS; i++) {
            final int idx = i;
            threads[1 + i] = new Thread(() -> {
                await(start);
                for (int round = 0; round < ROTATIONS * 3; round++) {
                    try {
                        var result = rewrap.rewrapWithResult(CTX, envelopes.get(idx));
                        envelopes.set(idx, result.envelope());
                        if (result.migrated()) {
                            rewrapMigrations.incrementAndGet();
                        }
                        Thread.sleep(2);
                    } catch (Throwable t) {
                        unexpected.add(t);
                    }
                }
            }, "rewrap-" + i);
        }

        // 解密线程：持续解密快照，明文必须始终正确
        for (int i = 0; i < RECORDS; i++) {
            final int idx = i;
            threads[1 + RECORDS + i] = new Thread(() -> {
                await(start);
                for (int round = 0; round < ROTATIONS * 3; round++) {
                    try {
                        byte[] got = cipher.decrypt(CTX, envelopes.get(idx));
                        if (!java.util.Arrays.equals(plaintexts[idx], got)) {
                            unexpected.add(new AssertionError("plaintext mismatch at record " + idx));
                        } else {
                            decryptSuccesses.incrementAndGet();
                        }
                        Thread.sleep(1);
                    } catch (Throwable t) {
                        unexpected.add(t);
                    }
                }
            }, "decrypt-" + i);
        }

        for (Thread t : threads) {
            t.start();
        }
        start.countDown();
        for (Thread t : threads) {
            t.join(TimeUnit.SECONDS.toMillis(30));
        }

        int finalVersion = keyRing.activeKey().orElseThrow().getVersion();
        log.info("concurrency done finalVersion={} rewrapMigrations={} decryptSuccesses={} unexpected={}",
                finalVersion, rewrapMigrations.get(), decryptSuccesses.get(), unexpected.size());

        assertTrue(unexpected.isEmpty(),
                "并发期间出现不可解释异常: " + (unexpected.isEmpty() ? "" : unexpected.peek()));
        assertEquals(initialVersion + ROTATIONS, finalVersion, "轮换必须有序单调");
        // 终态：所有记录都能解密出原始明文，且版本线索合法
        for (int i = 0; i < RECORDS; i++) {
            String current = envelopes.get(i);
            int version = CiphertextEnvelope.parse(current).kekVersion();
            assertTrue(version >= initialVersion && version <= finalVersion,
                    "版本线索越界: " + version);
            assertArrayEquals(plaintexts[i], cipher.decrypt(CTX, current),
                    "记录 " + i + " 在并发后明文必须可恢复");
        }
        // 幂等终态：全部重包裹到最终版本后再次提交均为 no-op
        for (int i = 0; i < RECORDS; i++) {
            var settled = rewrap.rewrapWithResult(CTX, envelopes.get(i));
            var again = rewrap.rewrapWithResult(CTX, settled.envelope());
            assertEquals(settled.envelope(), again.envelope());
            assertTrue(!again.migrated());
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
