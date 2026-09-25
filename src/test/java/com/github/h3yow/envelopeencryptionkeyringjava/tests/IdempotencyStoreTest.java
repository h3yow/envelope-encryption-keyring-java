package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.envelopeencryptionkeyringjava.config.EekrProperties;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CryptoException;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.ErrorCode;
import com.github.h3yow.envelopeencryptionkeyringjava.service.IdempotencyRecord;
import com.github.h3yow.envelopeencryptionkeyringjava.service.IdempotencyStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class IdempotencyStoreTest {

    private static final Logger log = LoggerFactory.getLogger(IdempotencyStoreTest.class);

    private IdempotencyStore store(Path dir) {
        return new IdempotencyStore(dir, new ObjectMapper(), new EekrProperties(
                dir.toString(), "p", 1000, "a", "u",
                new EekrProperties.Idempotency(10)));
    }

    @Test
    void recordSurvivesRestartAndConflictIsDetected(@TempDir Path dir) {
        IdempotencyStore first = store(dir);
        assertNull(first.find("rid", "digest-A"));
        var rec = new IdempotencyRecord("rid", "digest-A", "CT-v2", "v2", 1L);
        assertSame(rec, first.commitIfAbsent(rec));

        // 模拟重启：新实例、空内存缓存，仅靠磁盘恢复
        IdempotencyStore second = store(dir);
        IdempotencyRecord loaded = second.find("rid", "digest-A");
        assertNotNull(loaded);
        assertEquals("CT-v2", loaded.outputCiphertext());
        assertEquals("v2", loaded.outputVersion());
        log.info("idempotency persistence: requestId=rid basis=disk-reload outputVersion=v2");

        // 同 requestId + 不同输入 -> 冲突
        CryptoException ex = assertThrows(CryptoException.class,
                () -> second.find("rid", "digest-B"));
        assertEquals(ErrorCode.IDEMPOTENCY_CONFLICT, ex.getErrorCode());
    }

    @Test
    void unsafeRequestIdRejected(@TempDir Path dir) {
        IdempotencyStore s = store(dir);
        assertEquals(ErrorCode.INVALID_REQUEST, assertThrows(CryptoException.class,
                () -> s.find("../escape", "d")).getErrorCode());
    }
}
