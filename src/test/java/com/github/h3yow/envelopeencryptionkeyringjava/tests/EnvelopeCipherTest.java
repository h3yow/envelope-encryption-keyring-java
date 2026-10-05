package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CiphertextEnvelope;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.EnvelopeCipher;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyRing;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyRingProtection;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.MasterKeyService;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.CiphertextIntegrityException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.ContextMismatchException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.CryptoServiceException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.KeyDisabledException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.MalformedCiphertextException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.UnknownKeyVersionException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;

/** 信封加解密：往返、DEK 独立性、篡改、上下文不匹配、版本异常。 */
class EnvelopeCipherTest {

    private static final Logger log = LoggerFactory.getLogger(EnvelopeCipherTest.class);
    private static final String CTX = "tenant=alpha;purpose=billing";

    @TempDir
    Path dir;

    KeyRing keyRing;
    EnvelopeCipher cipher;

    @BeforeEach
    void setUp() {
        keyRing = new KeyRing(dir.resolve("keyring.json").toString(), KeyRingProtection.fromRootKey("test-root-key"));
        MasterKeyService admin = new MasterKeyService(keyRing, "tok", false);
        admin.ensureInitialized();
        cipher = new EnvelopeCipher(keyRing);
    }

    private static String digest(byte[] data) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data))
                .substring(0, 16);
    }

    @Test
    void roundTripPreservesPlaintext() throws Exception {
        byte[] plaintext = "hello envelope".getBytes(StandardCharsets.UTF_8);
        String envelope = cipher.encrypt(CTX, plaintext);
        CiphertextEnvelope parsed = CiphertextEnvelope.parse(envelope);
        log.info("roundTrip inputDigest={} kekVersion={} envelopeSegments=7",
                digest(plaintext), parsed.kekVersion());
        byte[] restored = cipher.decrypt(CTX, envelope);
        assertArrayEquals(plaintext, restored);
    }

    @Test
    void eachEncryptionUsesIndependentDek() {
        byte[] plaintext = "same input".getBytes(StandardCharsets.UTF_8);
        String a = cipher.encrypt(CTX, plaintext);
        String b = cipher.encrypt(CTX, plaintext);
        CiphertextEnvelope ea = CiphertextEnvelope.parse(a);
        CiphertextEnvelope eb = CiphertextEnvelope.parse(b);
        log.info("dekIndependence kekVersion={} wrappedDekEqual={} ciphertextEqual={}",
                ea.kekVersion(),
                MessageDigest.isEqual(ea.wrappedDek(), eb.wrappedDek()),
                MessageDigest.isEqual(ea.ciphertext(), eb.ciphertext()));
        assertNotEquals(a, b, "相同明文两次加密必须产生不同密文（独立 DEK）");
    }

    @Test
    void tamperedCiphertextRejectedAsIntegrity() {
        String envelope = cipher.encrypt(CTX, "secret".getBytes(StandardCharsets.UTF_8));
        CiphertextEnvelope e = CiphertextEnvelope.parse(envelope);
        byte[] tampered = e.ciphertext().clone();
        tampered[0] ^= 0x01;
        String bad = new CiphertextEnvelope(e.formatVersion(), e.kekVersion(), e.wrapIv(),
                e.wrappedDek(), e.dataIv(), tampered, e.contextTag()).encode();
        log.info("tamper kekVersion={} expectation=CiphertextIntegrityException", e.kekVersion());
        var ex = assertThrows(CiphertextIntegrityException.class, () -> cipher.decrypt(CTX, bad));
        // 底层密码学异常不得原样透出
        assertNotEquals(GeneralSecurityException.class, ex.getClass());
        assertTrue(ex instanceof CryptoServiceException);
    }

    @Test
    void tamperedWrappedDekRejectedAsIntegrity() {
        String envelope = cipher.encrypt(CTX, "secret".getBytes(StandardCharsets.UTF_8));
        CiphertextEnvelope e = CiphertextEnvelope.parse(envelope);
        byte[] tampered = e.wrappedDek().clone();
        tampered[0] ^= 0x01;
        String bad = new CiphertextEnvelope(e.formatVersion(), e.kekVersion(), e.wrapIv(),
                tampered, e.dataIv(), e.ciphertext(), e.contextTag()).encode();
        log.info("wrapTamper kekVersion={} expectation=CiphertextIntegrityException", e.kekVersion());
        assertThrows(CiphertextIntegrityException.class, () -> cipher.decrypt(CTX, bad));
    }

    @Test
    void contextMismatchRejectedSeparately() {
        String envelope = cipher.encrypt(CTX, "secret".getBytes(StandardCharsets.UTF_8));
        CiphertextEnvelope e = CiphertextEnvelope.parse(envelope);
        log.info("contextMismatch kekVersion={} wrongCtx={} expectation=ContextMismatchException",
                e.kekVersion(), "tenant=beta");
        assertThrows(ContextMismatchException.class,
                () -> cipher.decrypt("tenant=beta;purpose=billing", envelope));
    }

    @Test
    void malformedCiphertextRejected() {
        log.info("malformed cases: empty / missing segments / bad version clue");
        assertThrows(MalformedCiphertextException.class, () -> cipher.decrypt(CTX, ""));
        assertThrows(MalformedCiphertextException.class, () -> cipher.decrypt(CTX, "EK1.1.abc"));
        assertThrows(MalformedCiphertextException.class,
                () -> cipher.decrypt(CTX, "EK1.notanumber.aa.bb.cc.dd.ee"));
        assertThrows(MalformedCiphertextException.class,
                () -> cipher.decrypt(CTX, "XX1.1.aa.bb.cc.dd.ee"));
    }

    @Test
    void unknownVersionRejected() {
        String envelope = cipher.encrypt(CTX, "secret".getBytes(StandardCharsets.UTF_8));
        CiphertextEnvelope e = CiphertextEnvelope.parse(envelope);
        String bad = new CiphertextEnvelope(e.formatVersion(), e.kekVersion() + 100, e.wrapIv(),
                e.wrappedDek(), e.dataIv(), e.ciphertext(), e.contextTag()).encode();
        log.info("unknownVersion claimed={} expectation=UnknownKeyVersionException",
                e.kekVersion() + 100);
        assertThrows(UnknownKeyVersionException.class, () -> cipher.decrypt(CTX, bad));
    }

    @Test
    void disabledKeyRejected() {
        String envelope = cipher.encrypt(CTX, "secret".getBytes(StandardCharsets.UTF_8));
        int oldVersion = CiphertextEnvelope.parse(envelope).kekVersion();
        MasterKeyService admin = new MasterKeyService(keyRing, "tok", false);
        admin.rotate("tok");
        admin.disable("tok", oldVersion);
        log.info("disabledKey version={} activeVersion={} expectation=KeyDisabledException",
                oldVersion, keyRing.activeKey().orElseThrow().getVersion());
        assertThrows(KeyDisabledException.class, () -> cipher.decrypt(CTX, envelope));
        // 状态可恢复：新密文仍可正常加解密
        String fresh = cipher.encrypt(CTX, "new".getBytes(StandardCharsets.UTF_8));
        assertEquals("new", new String(cipher.decrypt(CTX, fresh), StandardCharsets.UTF_8));
    }
}
