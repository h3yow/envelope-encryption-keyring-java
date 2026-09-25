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
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.DecryptRequest;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.EncryptRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EncryptionServiceTest {

    private static final Logger log = LoggerFactory.getLogger(EncryptionServiceTest.class);

    private final CryptoService crypto = new CryptoService();

    private record Harness(EncryptionService service, KeyRing ring) {
    }

    private Harness harness(Path dir) {
        EekrProperties props = new EekrProperties(
                dir.toString(), "pass", 10000, "a", "u",
                new EekrProperties.Idempotency(100));
        KeyRing ring = new KeyRing(new FileKeyStore(dir.resolve("keyring.json"), new ObjectMapper()),
                crypto, props);
        return new Harness(new EncryptionService(ring, crypto), ring);
    }

    @Test
    void envelopeRoundTripUsesIndependentDeks(@org.junit.jupiter.api.io.TempDir Path dir) {
        Harness h = harness(dir);
        var r1 = h.service().encrypt(new EncryptRequest("payload-A", "tenant/42"));
        var r2 = h.service().encrypt(new EncryptRequest("payload-A", "tenant/42"));
        assertEquals("v1", r1.keyVersion());
        assertNotEquals(r1.ciphertext(), r2.ciphertext(), "两次加密必须产生不同密文（独立 DEK/IV）");
        // 密文头携带可解析版本线索
        var env = EnvelopeFormat.parse(Base64.getDecoder().decode(r1.ciphertext()));
        assertEquals("v1", env.keyVersion());

        var d1 = h.service().decrypt(new DecryptRequest(r1.ciphertext(), "tenant/42"));
        var d2 = h.service().decrypt(new DecryptRequest(r2.ciphertext(), "tenant/42"));
        assertEquals("payload-A", d1.plaintext());
        assertEquals("payload-A", d2.plaintext());
        log.info("round-trip: keyVersion=v1 inputSha256={} basis=tag-validated dekUniqueness=confirmed",
                com.github.h3yow.envelopeencryptionkeyringjava.crypto.DigestUtil.sha256Prefix("payload-A"));
    }

    @Test
    void contextMismatchRejectedBeforeCrypto(@org.junit.jupiter.api.io.TempDir Path dir) {
        Harness h = harness(dir);
        var enc = h.service().encrypt(new EncryptRequest("secret", "ctx-A"));
        CryptoException ex = assertThrows(CryptoException.class,
                () -> h.service().decrypt(new DecryptRequest(enc.ciphertext(), "ctx-B")));
        assertEquals(ErrorCode.CONTEXT_MISMATCH, ex.getErrorCode());
        log.info("context: keyVersion=v1 basis=context-hash-mismatch -> CONTEXT_MISMATCH");
    }

    @Test
    void tamperedDataCiphertextRejected(@org.junit.jupiter.api.io.TempDir Path dir) {
        Harness h = harness(dir);
        var enc = h.service().encrypt(new EncryptRequest("secret", "ctx"));
        byte[] raw = Base64.getDecoder().decode(enc.ciphertext());
        var parsed = EnvelopeFormat.parse(raw);
        byte[] ct = parsed.ciphertext().clone();
        ct[0] ^= 0x01;
        var tampered = new EnvelopeFormat.Envelope(parsed.keyVersion(), parsed.contextHash(),
                parsed.wrappedKeyIv(), parsed.wrappedKey(), parsed.dataIv(), ct);
        String bad = Base64.getEncoder().encodeToString(EnvelopeFormat.serialize(tampered));

        CryptoException ex = assertThrows(CryptoException.class,
                () -> h.service().decrypt(new DecryptRequest(bad, "ctx")));
        assertEquals(ErrorCode.CIPHERTEXT_TAMPERED, ex.getErrorCode());
        log.info("tamper(data): keyVersion=v1 basis=data-tag-invalid -> CIPHERTEXT_TAMPERED");
    }

    @Test
    void tamperedWrappedKeyRejected(@org.junit.jupiter.api.io.TempDir Path dir) {
        Harness h = harness(dir);
        var enc = h.service().encrypt(new EncryptRequest("secret", "ctx"));
        var parsed = EnvelopeFormat.parse(Base64.getDecoder().decode(enc.ciphertext()));
        byte[] wk = parsed.wrappedKey().clone();
        wk[0] ^= 0x01;
        var tampered = new EnvelopeFormat.Envelope(parsed.keyVersion(), parsed.contextHash(),
                parsed.wrappedKeyIv(), wk, parsed.dataIv(), parsed.ciphertext());
        String bad = Base64.getEncoder().encodeToString(EnvelopeFormat.serialize(tampered));

        CryptoException ex = assertThrows(CryptoException.class,
                () -> h.service().decrypt(new DecryptRequest(bad, "ctx")));
        assertEquals(ErrorCode.CIPHERTEXT_TAMPERED, ex.getErrorCode());
    }

    @Test
    void malformedAndInvalidBase64Rejected(@org.junit.jupiter.api.io.TempDir Path dir) {
        Harness h = harness(dir);
        assertEquals(ErrorCode.CIPHERTEXT_MALFORMED,
                assertThrows(CryptoException.class,
                        () -> h.service().decrypt(new DecryptRequest("not-base64!!!", "ctx")))
                        .getErrorCode());
        assertEquals(ErrorCode.CIPHERTEXT_MALFORMED,
                assertThrows(CryptoException.class,
                        () -> h.service().decrypt(new DecryptRequest(Base64.getEncoder()
                                .encodeToString("short".getBytes(StandardCharsets.UTF_8)), "ctx")))
                        .getErrorCode());
        assertEquals(ErrorCode.INVALID_REQUEST,
                assertThrows(CryptoException.class,
                        () -> h.service().encrypt(new EncryptRequest("", "ctx"))).getErrorCode());
        log.info("malformed: basis=base64-decode/structure-check -> CIPHERTEXT_MALFORMED");
    }

    @Test
    void decryptWithUnknownAndDisabledVersionsRejected(@org.junit.jupiter.api.io.TempDir Path dir) {
        Harness h = harness(dir);
        var enc = h.service().encrypt(new EncryptRequest("secret", "ctx"));
        h.ring.rotate("test"); // current=v2
        // 手工伪造 v99 版本线索的密文（结构合法但版本不存在）
        var parsed = EnvelopeFormat.parse(Base64.getDecoder().decode(enc.ciphertext()));
        String fake = Base64.getEncoder().encodeToString(EnvelopeFormat.serialize(
                new EnvelopeFormat.Envelope("v99", parsed.contextHash(),
                        parsed.wrappedKeyIv(), parsed.wrappedKey(), parsed.dataIv(),
                        parsed.ciphertext())));
        assertEquals(ErrorCode.KEY_VERSION_UNKNOWN,
                assertThrows(CryptoException.class,
                        () -> h.service().decrypt(new DecryptRequest(fake, "ctx"))).getErrorCode());

        // 新加密走 v2；停用 v1 后，旧密文拒绝解密
        var encV2 = h.service().encrypt(new EncryptRequest("secret2", "ctx"));
        assertEquals("v2", encV2.keyVersion());
        h.ring.disable("v1");
        assertEquals(ErrorCode.KEY_VERSION_DISABLED,
                assertThrows(CryptoException.class,
                        () -> h.service().decrypt(new DecryptRequest(enc.ciphertext(), "ctx")))
                        .getErrorCode());
        log.info("version policy: unknown=KEY_VERSION_UNKNOWN disabled=KEY_VERSION_DISABLED basis=keystore-lookup");
    }

    @Test
    void underlyingCryptoExceptionNotLeached(@org.junit.jupiter.api.io.TempDir Path dir) {
        Harness h = harness(dir);
        var enc = h.service().encrypt(new EncryptRequest("secret", "ctx"));
        CryptoException ex = assertThrows(CryptoException.class,
                () -> h.service().decrypt(new DecryptRequest(enc.ciphertext(), "other")));
        // 消息只含固定文案，不出现 AEADBadTag 等底层类名
        assertArrayEquals(new String[]{"encryption context does not match"},
                new String[]{ex.getMessage()});
        log.info("sanitization: exposed message fixed; crypto internals stay server-side");
    }
}
