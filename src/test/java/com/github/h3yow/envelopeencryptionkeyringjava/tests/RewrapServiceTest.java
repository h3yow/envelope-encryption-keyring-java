package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.envelopeencryptionkeyringjava.config.EekrProperties;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CryptoException;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CryptoService;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.EnvelopeFormat;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.ErrorCode;
import com.github.h3yow.envelopeencryptionkeyringjava.keyring.FileKeyStore;
import com.github.h3yow.envelopeencryptionkeyringjava.keyring.KeyRing;
import com.github.h3yow.envelopeencryptionkeyringjava.service.EncryptionService;
import com.github.h3yow.envelopeencryptionkeyringjava.service.IdempotencyStore;
import com.github.h3yow.envelopeencryptionkeyringjava.service.RewrapService;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.DecryptRequest;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.EncryptRequest;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.RewrapRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RewrapServiceTest {

    private static final Logger log = LoggerFactory.getLogger(RewrapServiceTest.class);
    private final CryptoService crypto = new CryptoService();

    private record Harness(EncryptionService enc, RewrapService rewrap, KeyRing ring) {
    }

    private Harness harness(Path dir) {
        EekrProperties props = new EekrProperties(
                dir.toString(), "pass", 10000, "a", "u",
                new EekrProperties.Idempotency(100));
        ObjectMapper mapper = new ObjectMapper();
        KeyRing ring = new KeyRing(new FileKeyStore(dir.resolve("keyring.json"), mapper), crypto, props);
        EncryptionService enc = new EncryptionService(ring, crypto);
        IdempotencyStore idem = new IdempotencyStore(dir.resolve("rewraps"), mapper, props);
        return new Harness(enc, new RewrapService(ring, crypto, idem), ring);
    }

    @Test
    void rewrapMigratesVersionButPreservesPlaintextAndDekCiphertext(@TempDir Path dir) {
        Harness h = harness(dir);
        var enc = h.enc.encrypt(new EncryptRequest("migrate-me", "ctx"));
        var before = EnvelopeFormat.parse(Base64.getDecoder().decode(enc.ciphertext()));
        assertEquals("v1", before.keyVersion());

        h.ring.rotate("test");
        var res = h.rewrap.rewrap(new RewrapRequest(enc.ciphertext(), "ctx", "req-1"));
        assertEquals("v2", res.keyVersion());
        assertFalse(res.replayed());
        assertNotEquals(enc.ciphertext(), res.ciphertext());

        var after = EnvelopeFormat.parse(Base64.getDecoder().decode(res.ciphertext()));
        assertEquals("v2", after.keyVersion());
        // DEK 语义不变：数据密文段与数据 IV 原样保留
        assertArrayEquals(before.ciphertext(), after.ciphertext());
        assertArrayEquals(before.dataIv(), after.dataIv());
        // 只有包裹段变化
        assertNotEquals(java.util.HexFormat.of().formatHex(before.wrappedKey()),
                java.util.HexFormat.of().formatHex(after.wrappedKey()));

        // 新密文可在新版本下解密出相同明文
        var dec = h.enc.decrypt(new DecryptRequest(res.ciphertext(), "ctx"));
        assertEquals("migrate-me", dec.plaintext());
        log.info("rewrap semantics: v1->v2 basis=dek-and-dataciphertext-preserved plaintextSha256={}",
                com.github.h3yow.envelopeencryptionkeyringjava.crypto.DigestUtil.sha256Prefix("migrate-me"));
    }

    @Test
    void duplicateRequestIsIdempotent(@TempDir Path dir) {
        Harness h = harness(dir);
        var enc = h.enc.encrypt(new EncryptRequest("x", "ctx"));
        h.ring.rotate("test");

        var first = h.rewrap.rewrap(new RewrapRequest(enc.ciphertext(), "ctx", "dup-1"));
        var second = h.rewrap.rewrap(new RewrapRequest(enc.ciphertext(), "ctx", "dup-1"));
        var third = h.rewrap.rewrap(new RewrapRequest(enc.ciphertext(), "ctx", "dup-1"));
        assertFalse(first.replayed());
        assertTrue(second.replayed());
        assertTrue(third.replayed());
        assertEquals(first.ciphertext(), second.ciphertext());
        assertEquals(first.ciphertext(), third.ciphertext());
        log.info("idempotency: requestId=dup-1 basis=stored-record-hit outputs-identical=true");
    }

    @Test
    void sameRequestIdDifferentPayloadConflicts(@TempDir Path dir) {
        Harness h = harness(dir);
        var a = h.enc.encrypt(new EncryptRequest("a", "ctx"));
        var b = h.enc.encrypt(new EncryptRequest("b", "ctx"));
        h.ring.rotate("test");
        h.rewrap.rewrap(new RewrapRequest(a.ciphertext(), "ctx", "rid"));
        CryptoException ex = assertThrows(CryptoException.class,
                () -> h.rewrap.rewrap(new RewrapRequest(b.ciphertext(), "ctx", "rid")));
        assertEquals(ErrorCode.IDEMPOTENCY_CONFLICT, ex.getErrorCode());
        log.info("idempotency conflict: requestId=rid basis=input-digest-differs -> IDEMPOTENCY_CONFLICT");
    }

    @Test
    void alreadyCurrentIsNoOp(@TempDir Path dir) {
        Harness h = harness(dir);
        var enc = h.enc.encrypt(new EncryptRequest("x", "ctx")); // v1 current
        var res = h.rewrap.rewrap(new RewrapRequest(enc.ciphertext(), "ctx", "noop"));
        assertEquals("v1", res.keyVersion());
        assertEquals(enc.ciphertext(), res.ciphertext());
        assertFalse(res.replayed());
        log.info("rewrap no-op: keyVersion=v1 basis=already-current");
    }

    @Test
    void rewrapRejectsContextMismatchAndTamper(@TempDir Path dir) {
        Harness h = harness(dir);
        var enc = h.enc.encrypt(new EncryptRequest("x", "ctx-A"));
        h.ring.rotate("test");

        assertEquals(ErrorCode.CONTEXT_MISMATCH, assertThrows(CryptoException.class,
                () -> h.rewrap.rewrap(new RewrapRequest(enc.ciphertext(), "ctx-B", "r1")))
                .getErrorCode());

        var parsed = EnvelopeFormat.parse(Base64.getDecoder().decode(enc.ciphertext()));
        byte[] wk = parsed.wrappedKey().clone();
        wk[0] ^= 0x01;
        String tampered = Base64.getEncoder().encodeToString(EnvelopeFormat.serialize(
                new EnvelopeFormat.Envelope(parsed.keyVersion(), parsed.contextHash(),
                        parsed.wrappedKeyIv(), wk, parsed.dataIv(), parsed.ciphertext())));
        assertEquals(ErrorCode.CIPHERTEXT_TAMPERED, assertThrows(CryptoException.class,
                () -> h.rewrap.rewrap(new RewrapRequest(tampered, "ctx-A", "r2")))
                .getErrorCode());

        assertEquals(ErrorCode.INVALID_REQUEST, assertThrows(CryptoException.class,
                () -> h.rewrap.rewrap(new RewrapRequest(enc.ciphertext(), "ctx-A", " ")))
                .getErrorCode());
        log.info("rewrap validation: context/tamper/requestId reasons distinguishable");
    }

    @Test
    void disabledSourceKeyCanStillBeMigrated(@TempDir Path dir) {
        Harness h = harness(dir);
        var enc = h.enc.encrypt(new EncryptRequest("legacy", "ctx")); // v1
        h.ring.rotate("test"); // current v2
        h.ring.disable("v1");  // v1 停用，解密被拒
        assertEquals(ErrorCode.KEY_VERSION_DISABLED, assertThrows(CryptoException.class,
                () -> h.enc.decrypt(new DecryptRequest(enc.ciphertext(), "ctx"))).getErrorCode());
        // 但管理员维护式迁移可把数据搬到 v2，迁移后恢复可解密
        var res = h.rewrap.rewrap(new RewrapRequest(enc.ciphertext(), "ctx", "migrate-disabled"));
        assertEquals("v2", res.keyVersion());
        assertEquals("legacy", h.enc.decrypt(new DecryptRequest(res.ciphertext(), "ctx")).plaintext());
        log.info("recovery: disabled v1 migrated to v2 basis=source-allowed-for-rewrap stateRecovered=true");
    }
}
