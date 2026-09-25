package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyRing;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyStatus;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.MasterKey;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.MasterKeyService;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.UnauthorizedOperationException;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 主密钥管理：鉴权边界、有序轮换、停用规则、本地持久化恢复。 */
class MasterKeyServiceTest {

    private static final Logger log = LoggerFactory.getLogger(MasterKeyServiceTest.class);
    private static final String ADMIN = "admin-token";

    @TempDir
    Path dir;

    KeyRing keyRing;
    MasterKeyService service;

    @BeforeEach
    void setUp() {
        keyRing = new KeyRing(dir.resolve("keyring.json").toString());
        service = new MasterKeyService(keyRing, ADMIN, false);
    }

    @Test
    void unauthorizedCallerCannotRotateOrDisable() {
        service.ensureInitialized();
        log.info("unauth callerToken=<empty>/<wrong> expectation=UnauthorizedOperationException");
        assertThrows(UnauthorizedOperationException.class, () -> service.rotate(""));
        assertThrows(UnauthorizedOperationException.class, () -> service.rotate("wrong-token"));
        assertThrows(UnauthorizedOperationException.class, () -> service.rotate(null));
        assertThrows(UnauthorizedOperationException.class, () -> service.disable("wrong", 1));
        // 鉴权失败后密钥环状态不变
        assertEquals(1, keyRing.size());
    }

    @Test
    void emptyConfiguredTokenRejectsEverything() {
        MasterKeyService locked = new MasterKeyService(keyRing, "", false);
        log.info("emptyAdminToken expectation=all admin ops rejected");
        assertThrows(UnauthorizedOperationException.class, () -> locked.rotate(""));
    }

    @Test
    void rotationIsOrderedAndMonotonic() {
        MasterKey k1 = service.ensureInitialized();
        MasterKey k2 = service.rotate(ADMIN);
        MasterKey k3 = service.rotate(ADMIN);
        log.info("orderedRotation versions={},{},{}", k1.getVersion(), k2.getVersion(), k3.getVersion());
        assertTrue(k1.getVersion() < k2.getVersion());
        assertTrue(k2.getVersion() < k3.getVersion());
        assertEquals(k3.getVersion(), keyRing.activeKey().orElseThrow().getVersion());
    }

    @Test
    void disablingLastActiveKeyRejected() {
        MasterKey k1 = service.ensureInitialized();
        log.info("disableLastActive version={} expectation=IllegalStateException", k1.getVersion());
        assertThrows(IllegalStateException.class, () -> service.disable(ADMIN, k1.getVersion()));
        assertEquals(KeyStatus.ACTIVE, keyRing.find(k1.getVersion()).orElseThrow().getStatus());
    }

    @Test
    void disablingNonActiveKeySucceeds() {
        MasterKey k1 = service.ensureInitialized();
        MasterKey k2 = service.rotate(ADMIN);
        service.disable(ADMIN, k1.getVersion());
        log.info("disableNonActive disabled={} active={}", k1.getVersion(), k2.getVersion());
        assertEquals(KeyStatus.DISABLED, keyRing.find(k1.getVersion()).orElseThrow().getStatus());
        assertEquals(KeyStatus.ACTIVE, keyRing.find(k2.getVersion()).orElseThrow().getStatus());
    }

    @Test
    void stateSurvivesReloadFromDisk() {
        MasterKey k1 = service.ensureInitialized();
        MasterKey k2 = service.rotate(ADMIN);
        service.disable(ADMIN, k1.getVersion());
        KeyRing reloaded = new KeyRing(dir.resolve("keyring.json").toString());
        log.info("reload highestVersion={} size={}", reloaded.highestVersion(), reloaded.size());
        assertEquals(k2.getVersion(), reloaded.activeKey().orElseThrow().getVersion());
        assertEquals(KeyStatus.DISABLED, reloaded.find(k1.getVersion()).orElseThrow().getStatus());
        // 轮换在重载后继续保持有序
        MasterKeyService service2 = new MasterKeyService(reloaded, ADMIN, false);
        assertEquals(k2.getVersion() + 1, service2.rotate(ADMIN).getVersion());
    }
}
