package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.envelopeencryptionkeyringjava.config.EekrProperties;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CryptoException;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CryptoService;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.ErrorCode;
import com.github.h3yow.envelopeencryptionkeyringjava.keyring.FileKeyStore;
import com.github.h3yow.envelopeencryptionkeyringjava.keyring.KeyRing;
import com.github.h3yow.envelopeencryptionkeyringjava.keyring.KeyStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyRingTest {

    private static final Logger log = LoggerFactory.getLogger(KeyRingTest.class);

    private KeyRing newRing(Path dir) {
        EekrProperties props = new EekrProperties(
                dir.toString(), "test-pass", 10000, "a", "u",
                new EekrProperties.Idempotency(100));
        FileKeyStore store = new FileKeyStore(dir.resolve("keyring.json"), new ObjectMapper());
        return new KeyRing(store, new CryptoService(), props);
    }

    @Test
    void bootstrapCreatesV1AndPersists(@TempDir Path dir) {
        KeyRing ring = newRing(dir);
        assertEquals("v1", ring.currentKey().version());
        assertTrue(dir.resolve("keyring.json").toFile().isFile());
        log.info("bootstrap: keyVersion=v1 basis=auto-create-on-empty-store");

        // 重新加载：状态与版本计数延续，且主密钥可正确解包
        KeyRing reloaded = newRing(dir);
        assertEquals("v1", reloaded.currentKey().version());
        log.info("reload: keyVersion=v1 basis=wrapped-material-unwrapped-with-derived-root-key");
    }

    @Test
    void rotationIsOrderedAndOldKeyRemainsEnabled(@TempDir Path dir) {
        KeyRing ring = newRing(dir);
        String v2 = ring.rotate("test");
        String v3 = ring.rotate("test");
        assertEquals("v2", v2);
        assertEquals("v3", v3);
        assertEquals("v3", ring.currentKey().version());

        List<KeyRing.KeyViewSnapshot> views = ring.listVersions();
        assertEquals(3, views.size());
        for (KeyRing.KeyViewSnapshot v : views) {
            assertEquals(KeyStatus.ENABLED.name(), v.status());
            assertEquals(v.version().equals("v3"), v.current());
        }
        // 旧版本仍可取用解密
        assertEquals("v1", ring.keyForDecryption("v1").version());
        log.info("rotation: versions=v1,v2,v3 current=v3 basis=monotonic-counter oldKeys=enabled");
    }

    @Test
    void unknownAndDisabledVersionsRejectedDistinctly(@TempDir Path dir) {
        KeyRing ring = newRing(dir);
        ring.rotate("test"); // current=v2，v1 可停用

        CryptoException unknown = assertThrows(CryptoException.class,
                () -> ring.keyForDecryption("v99"));
        assertEquals(ErrorCode.KEY_VERSION_UNKNOWN, unknown.getErrorCode());

        assertTrue(ring.disable("v1"));
        CryptoException disabled = assertThrows(CryptoException.class,
                () -> ring.keyForDecryption("v1"));
        assertEquals(ErrorCode.KEY_VERSION_DISABLED, disabled.getErrorCode());

        // 重复停用幂等
        assertFalse(ring.disable("v1"));
        // 当前版本禁止停用
        CryptoException current = assertThrows(CryptoException.class, () -> ring.disable("v2"));
        assertEquals(ErrorCode.INVALID_REQUEST, current.getErrorCode());

        // 停用状态持久化
        KeyRing reloaded = newRing(dir);
        assertEquals(ErrorCode.KEY_VERSION_DISABLED,
                assertThrows(CryptoException.class, () -> reloaded.keyForDecryption("v1")).getErrorCode());
        log.info("disable: keyVersion=v1 basis=status-check; reasons distinguishable=unknown/disabled/current");
    }

    @Test
    void disabledKeyStillAllowedForRewrapSource(@TempDir Path dir) {
        KeyRing ring = newRing(dir);
        ring.rotate("test");
        ring.disable("v1");
        // 迁移停用密钥下的数据合法：源材料仍可取
        assertEquals("v1", ring.keyForRewrapSource("v1").version());
    }
}
