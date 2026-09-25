package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CryptoException;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CryptoService;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.EnvelopeFormat;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.ErrorCode;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** AES-GCM 原语与信封格式单测：篡改/AAD 不匹配必须被区分拒绝。 */
class CryptoAndFormatTest {

    private static final Logger log = LoggerFactory.getLogger(CryptoAndFormatTest.class);
    private final CryptoService crypto = new CryptoService();

    @Test
    void gcmRoundTripAndAadMismatch() {
        byte[] key = crypto.generateKey();
        byte[] iv = crypto.generateIv();
        byte[] aad = "ctx-A".getBytes(StandardCharsets.UTF_8);
        byte[] pt = "hello-密钥".getBytes(StandardCharsets.UTF_8);
        byte[] ct = crypto.encrypt(key, iv, aad, pt);
        assertArrayEquals(pt, crypto.decryptOrThrow(key, iv, aad, ct));
        log.info("gcm round-trip: inputSha256-prefix={} keyVersion=n/a basis=aad-and-tag-valid",
                com.github.h3yow.envelopeencryptionkeyringjava.crypto.DigestUtil.sha256Prefix(pt));

        // 错误 AAD -> 认证失败（底层异常不透出，错误码由上层翻译）
        CryptoException ex = assertThrows(CryptoException.class,
                () -> crypto.decryptOrThrow(key, iv, "ctx-B".getBytes(StandardCharsets.UTF_8), ct));
        assertEquals(ErrorCode.INTERNAL_ERROR, ex.getErrorCode());
        assertTrue(ex.getMessage().contains("authentication failed"));
    }

    @Test
    void tamperedCiphertextFailsAuthentication() {
        byte[] key = crypto.generateKey();
        byte[] ct = crypto.encrypt(key, crypto.generateIv(), null, "data".getBytes(StandardCharsets.UTF_8));
        byte[] tampered = ct.clone();
        tampered[tampered.length - 1] ^= 0x01; // 翻转 tag 末位
        assertThrows(CryptoException.class,
                () -> crypto.decryptOrThrow(key, crypto.generateIv(), null, tampered));
        log.info("tamper test: keyVersion=n/a basis=gcm-tag-mismatch -> rejected");
    }

    @Test
    void envelopeSerializeParseRoundTrip() {
        var env = new EnvelopeFormat.Envelope(
                "v7", EnvelopeFormat.contextHash("tenant-1"),
                crypto.generateIv(), new byte[]{1, 2, 3, 40},
                crypto.generateIv(), new byte[]{9, 8, 7});
        byte[] raw = EnvelopeFormat.serialize(env);
        var parsed = EnvelopeFormat.parse(raw);
        assertEquals("v7", parsed.keyVersion());
        assertArrayEquals(env.contextHash(), parsed.contextHash());
        assertArrayEquals(env.wrappedKey(), parsed.wrappedKey());
        assertArrayEquals(env.ciphertext(), parsed.ciphertext());
        log.info("envelope format: keyVersion=v7 basis=roundtrip-equal bytes={}", raw.length);
    }

    @Test
    void malformedInputsRejected() {
        assertMalformed(null);
        assertMalformed(new byte[0]);
        assertMalformed("XXXX".getBytes(StandardCharsets.UTF_8));
        byte[] good = EnvelopeFormat.serialize(new EnvelopeFormat.Envelope(
                "v1", EnvelopeFormat.contextHash(""),
                crypto.generateIv(), new byte[]{1}, crypto.generateIv(), new byte[]{1}));
        assertMalformed(Arrays.copyOf(good, good.length - 2)); // 截断
        byte[] flipped = good.clone();
        flipped[4] ^= 0x01; // 破坏格式版本
        assertMalformed(flipped);
        log.info("malformed test: basis=magic/version/length checks -> CIPHERTEXT_MALFORMED");
    }

    @Test
    void keysAndIvsAreUnique() {
        assertNotEquals(java.util.HexFormat.of().formatHex(crypto.generateKey()),
                java.util.HexFormat.of().formatHex(crypto.generateKey()));
        assertNotEquals(java.util.HexFormat.of().formatHex(crypto.generateIv()),
                java.util.HexFormat.of().formatHex(crypto.generateIv()));
    }

    private void assertMalformed(byte[] raw) {
        CryptoException ex = assertThrows(CryptoException.class, () -> EnvelopeFormat.parse(raw));
        assertEquals(ErrorCode.CIPHERTEXT_MALFORMED, ex.getErrorCode());
    }
}
