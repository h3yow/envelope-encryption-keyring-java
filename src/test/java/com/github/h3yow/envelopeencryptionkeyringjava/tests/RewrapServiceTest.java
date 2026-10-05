package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CiphertextEnvelope;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.EnvelopeCipher;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyRing;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyRingProtection;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.MasterKeyService;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.RewrapService;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.ContextMismatchException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.KeyDisabledException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 重包裹迁移：明文/DEK 语义不变、幂等、错误可区分。 */
class RewrapServiceTest {

    private static final Logger log = LoggerFactory.getLogger(RewrapServiceTest.class);
    private static final String CTX = "tenant=alpha";
    private static final String ADMIN = "tok";

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
    void rewrapMigratesToCurrentVersionAndPreservesPlaintext() {
        byte[] plaintext = "migrate me".getBytes(StandardCharsets.UTF_8);
        String old = cipher.encrypt(CTX, plaintext);
        int fromVersion = CiphertextEnvelope.parse(old).kekVersion();
        admin.rotate(ADMIN);
        int toVersion = keyRing.activeKey().orElseThrow().getVersion();

        RewrapService.RewrapResult result = rewrap.rewrapWithResult(CTX, old);
        log.info("rewrap fromVersion={} toVersion={} migrated={}",
                result.fromVersion(), result.toVersion(), result.migrated());
        assertTrue(result.migrated());
        assertEquals(fromVersion, result.fromVersion());
        assertEquals(toVersion, result.toVersion());
        assertEquals(toVersion, CiphertextEnvelope.parse(result.envelope()).kekVersion());
        // 迁移前后明文语义不变
        assertArrayEquals(plaintext, cipher.decrypt(CTX, result.envelope()));
        // 数据密文段未被触碰（DEK 语义不变）
        CiphertextEnvelope before = CiphertextEnvelope.parse(old);
        CiphertextEnvelope after = CiphertextEnvelope.parse(result.envelope());
        assertArrayEquals(before.ciphertext(), after.ciphertext());
        assertArrayEquals(before.dataIv(), after.dataIv());
        assertArrayEquals(before.contextTag(), after.contextTag());
    }

    @Test
    void rewrapIsIdempotent() {
        String old = cipher.encrypt(CTX, "data".getBytes(StandardCharsets.UTF_8));
        admin.rotate(ADMIN);
        RewrapService.RewrapResult first = rewrap.rewrapWithResult(CTX, old);
        RewrapService.RewrapResult second = rewrap.rewrapWithResult(CTX, first.envelope());
        log.info("idempotent firstMigrated={} secondMigrated={} equal={}",
                first.migrated(), second.migrated(), first.envelope().equals(second.envelope()));
        assertTrue(first.migrated());
        assertFalse(second.migrated(), "重复提交同一迁移请求必须幂等");
        assertEquals(first.envelope(), second.envelope());
    }

    @Test
    void rewrapWithWrongContextRejected() {
        String old = cipher.encrypt(CTX, "data".getBytes(StandardCharsets.UTF_8));
        admin.rotate(ADMIN);
        log.info("rewrapContextMismatch expectation=ContextMismatchException");
        assertThrows(ContextMismatchException.class, () -> rewrap.rewrap("tenant=beta", old));
    }

    @Test
    void rewrapFromDisabledKeyRejected() {
        String old = cipher.encrypt(CTX, "data".getBytes(StandardCharsets.UTF_8));
        int oldVersion = CiphertextEnvelope.parse(old).kekVersion();
        admin.rotate(ADMIN);
        admin.disable(ADMIN, oldVersion);
        log.info("rewrapDisabled version={} expectation=KeyDisabledException", oldVersion);
        assertThrows(KeyDisabledException.class, () -> rewrap.rewrap(CTX, old));
    }
}
