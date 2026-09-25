package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.envelopeencryptionkeyringjava.config.EekrProperties;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CryptoService;
import com.github.h3yow.envelopeencryptionkeyringjava.keyring.FileKeyStore;
import com.github.h3yow.envelopeencryptionkeyringjava.keyring.KeyRing;
import com.github.h3yow.envelopeencryptionkeyringjava.service.EncryptionService;
import com.github.h3yow.envelopeencryptionkeyringjava.service.IdempotencyStore;
import com.github.h3yow.envelopeencryptionkeyringjava.service.RewrapService;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.DecryptRequest;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.EncryptRequest;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.RewrapRequest;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.RewrapResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并发场景：
 * 1) 多个密文在持续轮换下并发重包裹 + 并发解密：所有结果必须可解释、可恢复；
 * 2) 同一密文、同一 requestId 并发重包裹：只能产生一个结果（幂等不重复处理）。
 */
class ConcurrentRotationRewrapTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentRotationRewrapTest.class);
    private final CryptoService crypto = new CryptoService();

    private record Harness(EncryptionService enc, RewrapService rewrap, KeyRing ring) {
    }

    private Harness harness(Path dir) {
        EekrProperties props = new EekrProperties(
                dir.toString(), "pass", 10000, "a", "u",
                new EekrProperties.Idempotency(1000));
        ObjectMapper mapper = new ObjectMapper();
        KeyRing ring = new KeyRing(new FileKeyStore(dir.resolve("keyring.json"), mapper), crypto, props);
        EncryptionService enc = new EncryptionService(ring, crypto);
        IdempotencyStore idem = new IdempotencyStore(dir.resolve("rewraps"), mapper, props);
        return new Harness(enc, new RewrapService(ring, crypto, idem), ring);
    }

    @Test
    void concurrentRotationRewrapAndDecryptIsConsistent(@TempDir Path dir) throws Exception {
        Harness h = harness(dir);
        int cipherCount = 24;
        List<String> ciphertexts = new ArrayList<>();
        List<String> plains = new ArrayList<>();
        for (int i = 0; i < cipherCount; i++) {
            String plain = "message-" + i;
            plains.add(plain);
            ciphertexts.add(h.enc.encrypt(new EncryptRequest(plain, "ctx")).ciphertext());
        }

        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        Set<String> migratedVersions = ConcurrentHashMap.newKeySet();
        Set<String> failures = ConcurrentHashMap.newKeySet();

        // 4 个持续轮换者：产生 v2..v7
        for (int r = 0; r < 4; r++) {
            futures.add(pool.submit(() -> {
                await(start);
                for (int k = 0; k < 6; k++) {
                    String v = h.ring.rotate("concurrent");
                    migratedVersions.add(v);
                }
            }));
        }
        // 密文搬运者：每个密文反复重包裹直到它到达某个 >= v2 版本，再解密验证
        for (int i = 0; i < cipherCount; i++) {
            final int idx = i;
            futures.add(pool.submit(() -> {
                await(start);
                try {
                    String ct = ciphertexts.get(idx);
                    // 最多重包裹到追平当前版本；每次结果要么 no-op 要么版本单调向前
                    for (int attempt = 0; attempt < 8; attempt++) {
                        RewrapResponse rr = h.rewrap.rewrap(
                                new RewrapRequest(ct, "ctx", "m-" + idx + "-" + attempt));
                        ct = rr.ciphertext();
                        if (!rr.replayed()) {
                            migratedVersions.add(rr.keyVersion());
                        }
                        if (rr.keyVersion().equals(h.ring.listVersions().stream()
                                .filter(KeyRing.KeyViewSnapshot::current)
                                .map(KeyRing.KeyViewSnapshot::version).findFirst().orElseThrow())) {
                            break;
                        }
                    }
                    // 最终态必须能解密回原文 —— 无不可恢复数据
                    String decrypted = h.enc.decrypt(new DecryptRequest(ct, "ctx")).plaintext();
                    if (!decrypted.equals(plains.get(idx))) {
                        failures.add("plaintext mismatch idx=" + idx);
                    }
                } catch (Exception e) {
                    failures.add("idx=" + idx + " " + e.getClass().getSimpleName() + ":" + e.getMessage());
                }
            }));
        }
        // 纯解密者：轮换期间旧密文只要未停用就必须持续可解密
        for (int i = 0; i < 8; i++) {
            final int idx = i;
            futures.add(pool.submit(() -> {
                await(start);
                try {
                    String p = h.enc.decrypt(new DecryptRequest(ciphertexts.get(idx), "ctx")).plaintext();
                    if (!p.equals(plains.get(idx))) {
                        failures.add("decryptor mismatch idx=" + idx);
                    }
                } catch (Exception e) {
                    failures.add("decryptor idx=" + idx + " " + e.getClass().getSimpleName());
                }
            }));
        }

        start.countDown();
        for (Future<?> f : futures) {
            f.get(60, TimeUnit.SECONDS);
        }
        pool.shutdownNow();

        log.info("concurrent mixed: rotations={} failures={} basis=read/write-lock+snapshot versionsObserved={}",
                migratedVersions, failures.size(), migratedVersions);
        assertTrue(failures.isEmpty(), "并发结果必须全部可解释可恢复: " + failures);
        assertTrue(migratedVersions.size() >= 2);
    }

    @Test
    void sameRequestIdConcurrentRewrapProducesSingleOutcome(@TempDir Path dir) throws Exception {
        Harness h = harness(dir);
        String ct = h.enc.encrypt(new EncryptRequest("once", "ctx")).ciphertext();
        h.ring.rotate("test"); // 确保需要真实迁移

        int n = 16;
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<RewrapResponse>> futures = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return h.rewrap.rewrap(new RewrapRequest(ct, "ctx", "hot-request-id"));
            }));
        }
        start.countDown();

        List<RewrapResponse> results = new ArrayList<>();
        for (Future<RewrapResponse> f : futures) {
            results.add(f.get(30, TimeUnit.SECONDS));
        }
        pool.shutdownNow();

        long replays = results.stream().filter(RewrapResponse::replayed).count();
        long firsts = results.stream().filter(r -> !r.replayed()).count();
        assertEquals(1, firsts, "只能有一次真实迁移");
        assertEquals(n - 1, replays, "其余全部为重放");
        long distinctOutputs = results.stream().map(RewrapResponse::ciphertext).distinct().count();
        assertEquals(1, distinctOutputs, "输出必须完全一致，无重复处理");
        assertEquals("once",
                h.enc.decrypt(new DecryptRequest(results.get(0).ciphertext(), "ctx")).plaintext());
        log.info("concurrent idempotency: threads={} firsts=1 replays={} distinctOutputs=1 basis=per-requestId-lock",
                n, replays);
    }

    @Test
    void rotationsAreOrderedUnderConcurrency(@TempDir Path dir) throws Exception {
        Harness h = harness(dir);
        int n = 20;
        ExecutorService pool = Executors.newFixedThreadPool(10);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<String>> futures = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return h.ring.rotate("contention");
            }));
        }
        start.countDown();
        List<String> versions = new ArrayList<>();
        for (Future<String> f : futures) {
            versions.add(f.get(30, TimeUnit.SECONDS));
        }
        pool.shutdownNow();
        // 写锁串行化：版本号集合恰好是 v2..v21，无重复无空洞
        assertEquals(n, versions.stream().distinct().count());
        List<String> expected = IntStream.rangeClosed(2, n + 1).mapToObj("v%d"::formatted).toList();
        assertTrue(versions.containsAll(expected));
        log.info("concurrent rotation: versions=v2..v{} basis=write-lock-serialized no-holes", n + 1);
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
