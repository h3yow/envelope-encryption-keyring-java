package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.EnvelopeCipher;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyRing;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyRingProtection;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.MasterKeyService;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.RewrapService;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.KeyRingUnlockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 密钥环落盘保护：新格式无明文材料、旧格式平滑升级、根口令缺失/错误被拒。 */
class KeyRingProtectionTest {

    private static final Logger log = LoggerFactory.getLogger(KeyRingProtectionTest.class);
    private static final String CTX = "tenant=protect";
    private static final String ADMIN = "tok";
    private static final String ROOT = "correct-root-key";

    @TempDir
    Path dir;

    private KeyRing openRing(String fileName, String rootKey) {
        return new KeyRing(dir.resolve(fileName).toString(),
                KeyRingProtection.fromRootKey(rootKey));
    }

    @Test
    void persistedFileContainsNoPlaintextKeyMaterial() throws Exception {
        KeyRing keyRing = openRing("v2.json", ROOT);
        MasterKeyService admin = new MasterKeyService(keyRing, ADMIN, false);
        admin.ensureInitialized();
        admin.rotate(ADMIN);
        String material = keyRing.activeKey().orElseThrow().getMaterialBase64();

        String raw = Files.readString(dir.resolve("v2.json"));
        log.info("v2File formatV2={} hasWrappedField={} leaksMaterial={} leaksMaterialField={}",
                raw.contains("\"formatVersion\":2"), raw.contains("wrappedMaterialBase64"),
                raw.contains(material), raw.contains("\"materialBase64\""));
        assertTrue(raw.contains("\"formatVersion\":2"), "落盘必须是 v2 格式");
        assertTrue(raw.contains("wrappedMaterialBase64"), "落盘必须是包裹后的材料");
        assertFalse(raw.contains("\"materialBase64\""), "落盘不得出现明文材料字段");
        assertFalse(raw.contains(material), "落盘不得包含任何明文密钥材料");
    }

    @Test
    void legacyPlaintextFileLoadsAndUpgradesAndOldCiphertextsStillDecrypt() throws Exception {
        // 1. 先以新格式生成一个密钥环，取出 v1 密钥材料，用来伪造“在用的旧格式文件”
        KeyRing source = openRing("source.json", ROOT);
        MasterKeyService sourceAdmin = new MasterKeyService(source, ADMIN, false);
        sourceAdmin.ensureInitialized();
        String material = source.activeKey().orElseThrow().getMaterialBase64();

        // 2. 手写旧格式（v1，明文材料）密钥环文件
        String legacy = "{\"keys\":[{\"version\":1,\"status\":\"ACTIVE\",\"materialBase64\":\""
                + material + "\",\"createdAt\":1790301794.570505602}]}";
        Path legacyPath = dir.resolve("legacy.json");
        Files.writeString(legacyPath, legacy);

        // 3. 旧格式文件必须能正常加载，且加载后平滑升级为 v2
        KeyRing upgraded = new KeyRing(legacyPath.toString(), KeyRingProtection.fromRootKey(ROOT));
        String rawAfter = Files.readString(legacyPath);
        log.info("legacyUpgrade upgradedToV2={} leaksMaterial={}",
                rawAfter.contains("\"formatVersion\":2"), rawAfter.contains(material));
        assertTrue(rawAfter.contains("\"formatVersion\":2"), "加载旧格式后必须立即升级为 v2 落盘");
        assertFalse(rawAfter.contains(material), "升级后文件不得再含明文材料");
        assertEquals(1, upgraded.highestVersion());

        // 4. 升级前发出的密文（用同一材料在新格式密钥环下加密）升级后照样能解
        EnvelopeCipher sourceCipher = new EnvelopeCipher(source);
        byte[] plaintext = "issued-before-upgrade".getBytes(StandardCharsets.UTF_8);
        String oldEnvelope = sourceCipher.encrypt(CTX, plaintext);
        EnvelopeCipher upgradedCipher = new EnvelopeCipher(upgraded);
        assertArrayEquals(plaintext, upgradedCipher.decrypt(CTX, oldEnvelope),
                "升级后之前发出的密文必须照样能解");

        // 5. 升级后轮换与迁移结论不变：轮换版本继续递增，旧密文可重包裹
        MasterKeyService upgradedAdmin = new MasterKeyService(upgraded, ADMIN, false);
        var rotated = upgradedAdmin.rotate(ADMIN);
        assertEquals(2, rotated.getVersion(), "升级后轮换必须继续有序递增");
        RewrapService rewrap = new RewrapService(upgraded);
        var result = rewrap.rewrapWithResult(CTX, oldEnvelope);
        assertTrue(result.migrated());
        assertEquals(1, result.fromVersion());
        assertEquals(2, result.toVersion());
        assertArrayEquals(plaintext, upgradedCipher.decrypt(CTX, result.envelope()));
        log.info("postUpgrade rotationOrdered=true rewrapConclusion={}->{} plaintextPreserved=true",
                result.fromVersion(), result.toVersion());
    }

    @Test
    void missingRootKeyRefused() {
        log.info("missingRootKey expectation=KeyRingUnlockException (blank/null)");
        KeyRingUnlockException blank = assertThrows(KeyRingUnlockException.class,
                () -> KeyRingProtection.fromRootKey(""));
        KeyRingUnlockException nullKey = assertThrows(KeyRingUnlockException.class,
                () -> KeyRingProtection.fromRootKey(null));
        KeyRingUnlockException noProtection = assertThrows(KeyRingUnlockException.class,
                () -> new KeyRing(dir.resolve("x.json").toString(), null));
        // 异常消息不得泄露口令或密钥材料
        for (var e : new KeyRingUnlockException[] {blank, nullKey, noProtection}) {
            assertFalse(e.getMessage().contains(ROOT), "异常消息不得泄露根口令");
        }
    }

    @Test
    void wrongRootKeyRefusedWithoutLeaking() {
        KeyRing keyRing = openRing("sealed.json", ROOT);
        new MasterKeyService(keyRing, ADMIN, false).ensureInitialized();

        String wrongRoot = "wrong-root-key";
        KeyRingUnlockException e = assertThrows(KeyRingUnlockException.class,
                () -> openRing("sealed.json", wrongRoot));
        log.info("wrongRootKey rejected=true messageLeaksRoot={}",
                e.getMessage().contains(wrongRoot) || e.getMessage().contains(ROOT));
        assertFalse(e.getMessage().contains(wrongRoot), "异常消息不得泄露口令");
        assertFalse(e.getMessage().contains(ROOT), "异常消息不得泄露口令");
    }

    @Test
    void legacyFileNotLoadedWhenRootKeyMissing() throws Exception {
        // 旧格式文件 + 未配置根口令：必须拒绝，不能退化成明文加载
        String legacy = "{\"keys\":[{\"version\":1,\"status\":\"ACTIVE\",\"materialBase64\":\""
                + java.util.Base64.getEncoder().encodeToString(new byte[32])
                + "\",\"createdAt\":1790301794.570505602}]}";
        Path legacyPath = dir.resolve("legacy-nokey.json");
        Files.writeString(legacyPath, legacy);
        log.info("legacyNoRootKey expectation=KeyRingUnlockException");
        assertThrows(KeyRingUnlockException.class,
                () -> new KeyRing(legacyPath.toString(), null));
        // 文件保持原样（未被改写）
        assertEquals(legacy, Files.readString(legacyPath));
    }

    @Test
    void wrappedFileSurvivesReloadWithSameRootKey() {
        KeyRing keyRing = openRing("reload.json", ROOT);
        MasterKeyService admin = new MasterKeyService(keyRing, ADMIN, false);
        admin.ensureInitialized();
        EnvelopeCipher cipher = new EnvelopeCipher(keyRing);
        byte[] plaintext = "reload-check".getBytes(StandardCharsets.UTF_8);
        String envelope = cipher.encrypt(CTX, plaintext);
        admin.rotate(ADMIN);

        // 同一根口令重新加载：密文仍可解、轮换继续有序
        KeyRing reloaded = openRing("reload.json", ROOT);
        EnvelopeCipher cipher2 = new EnvelopeCipher(reloaded);
        assertArrayEquals(plaintext, cipher2.decrypt(CTX, envelope));
        MasterKeyService admin2 = new MasterKeyService(reloaded, ADMIN, false);
        assertEquals(3, admin2.rotate(ADMIN).getVersion());
        log.info("reloadWithSameRootKey decryptOk=true rotationContinues=true");
    }
}
