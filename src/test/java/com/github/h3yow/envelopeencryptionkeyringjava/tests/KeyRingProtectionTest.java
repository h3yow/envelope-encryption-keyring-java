package com.github.h3yow.envelopeencryptionkeyringjava.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.EnvelopeCipher;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyMaterialProtector;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.KeyRing;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.MasterKeyService;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.KeyRingLockedException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 落盘保护：根口令包裹、旧格式平滑升级、口令缺失/错误被拒，且不泄露任何材料。 */
class KeyRingProtectionTest {

    private static final Logger log = LoggerFactory.getLogger(KeyRingProtectionTest.class);
    private static final String ADMIN = "tok";
    private static final String ROOT = "correct-horse-battery-staple";
    private static final String WRONG = "tr0ub4dor";
    private static final String CTX = "tenant=protected";

    @TempDir
    Path dir;

    private Path path() {
        return dir.resolve("keyring.json");
    }

    @Test
    void persistedFileContainsNoPlaintextKeyMaterial() throws Exception {
        KeyRing ring = new KeyRing(path().toString(), new KeyMaterialProtector(ROOT));
        new MasterKeyService(ring, ADMIN, false).ensureInitialized();
        String content = Files.readString(path());
        log.info("场景-落盘无明文 formatPresent={} fileBytes={}",
                content.contains("\"format\""), content.length());
        JsonNode node = new ObjectMapper().readTree(content);
        assertEquals(KeyMaterialProtector.FORMAT, node.path("format").asText());
        assertFalse(content.contains("materialBase64"), "受保护文件不得出现明文字段 materialBase64");
        assertFalse(content.contains("\"keys\""), "受保护文件不得包含明文 keys 结构");
        // 解出密文也不可能恰好包含主密钥 base64
        KeyRing reopened = new KeyRing(path().toString(), new KeyMaterialProtector(ROOT));
        String material = reopened.find(1).orElseThrow().getMaterialBase64();
        assertFalse(content.contains(material), "文件中不得出现主密钥材料原文");
    }

    @Test
    void legacyPlaintextKeyringUpgradesAndOldCiphertextStillDecrypts() throws Exception {
        // 1. 用旧明文格式建密钥环并产生历史密文
        KeyRing legacy = new KeyRing(path().toString());
        MasterKeyService legacyAdmin = new MasterKeyService(legacy, ADMIN, false);
        legacyAdmin.ensureInitialized();
        EnvelopeCipher legacyCipher = new EnvelopeCipher(legacy);
        byte[] plaintext = "legacy-secret".getBytes(StandardCharsets.UTF_8);
        String oldEnvelope = legacyCipher.encrypt(CTX, plaintext);
        int oldVersion = legacy.find(1).orElseThrow().getVersion();
        // 轮换一版，制造需要迁移的历史密文
        legacyAdmin.rotate(ADMIN);
        String oldMaterial = legacy.find(1).orElseThrow().getMaterialBase64();
        String before = Files.readString(path());
        assertTrue(before.contains("materialBase64"), "前置：旧文件是明文格式");

        // 2. 配置根口令重新加载 → 必须平滑升级成受保护格式
        KeyRing upgraded = new KeyRing(path().toString(), new KeyMaterialProtector(ROOT));
        String after = Files.readString(path());
        JsonNode node = JsonMapper.builder().build().readTree(after);
        log.info("场景-旧格式升级 format={} keysLoaded={} oldMaterialLeaked={}",
                node.path("format").asText(), upgraded.size(), after.contains(oldMaterial));
        assertEquals(KeyMaterialProtector.FORMAT, node.path("format").asText());
        assertEquals(2, upgraded.size(), "升级后所有历史版本必须仍在");
        assertFalse(after.contains(oldMaterial), "升级后文件不得再含任何明文主密钥材料");

        // 3. 升级前发出的密文照样可解
        EnvelopeCipher newCipher = new EnvelopeCipher(upgraded);
        assertArrayEquals(plaintext, newCipher.decrypt(CTX, oldEnvelope),
                "旧格式升级后历史密文必须仍可解密");

        // 4. 轮换/迁移结论不变：版本单调递增，旧密文可重包裹到新版本并解密
        MasterKeyService newAdmin = new MasterKeyService(upgraded, ADMIN, false);
        var rotated = newAdmin.rotate(ADMIN);
        assertEquals(3, rotated.getVersion(), "升级后续轮换版本号必须延续单调");
        var rewrap = new com.github.h3yow.envelopeencryptionkeyringjava.crypto.RewrapService(upgraded);
        var result = rewrap.rewrapWithResult(CTX, oldEnvelope);
        assertTrue(result.migrated());
        assertArrayEquals(plaintext, newCipher.decrypt(CTX, result.envelope()));
        log.info("场景-升级后续结论不变 fromVersion={} toVersion={}", oldVersion,
                result.toVersion());
    }

    @Test
    void wrongPasswordRejectedWithoutDegradingToPlaintext() throws Exception {
        KeyRing ring = new KeyRing(path().toString(), new KeyMaterialProtector(ROOT));
        new MasterKeyService(ring, ADMIN, false).ensureInitialized();

        KeyRingLockedException ex = assertThrows(KeyRingLockedException.class,
                () -> new KeyRing(path().toString(), new KeyMaterialProtector(WRONG)));
        log.info("场景-错误口令被拒 code=KEY_RING_LOCKED messageSafe={}",
                !ex.getMessage().contains(ROOT) && !ex.getMessage().contains(WRONG));
        assertFalse(ex.getMessage().contains(ROOT), "异常消息不得包含口令");

        // 用正确口令仍可正常打开（错误口令尝试不得破坏文件）
        KeyRing recovered = new KeyRing(path().toString(), new KeyMaterialProtector(ROOT));
        assertEquals(1, recovered.size());
        // 文件依旧是受保护格式
        String content = Files.readString(path());
        assertTrue(content.contains(KeyMaterialProtector.FORMAT));
        assertFalse(content.contains("materialBase64"));
    }

    @Test
    void protectedFileWithoutPasswordIsRejectedAndNeverLoadedAsPlaintext() throws Exception {
        KeyRing ring = new KeyRing(path().toString(), new KeyMaterialProtector(ROOT));
        new MasterKeyService(ring, ADMIN, false).ensureInitialized();
        String material = ring.find(1).orElseThrow().getMaterialBase64();

        // 无保护构造方式打开受保护文件：必须拒绝，绝不按明文降级
        KeyRingLockedException ex = assertThrows(KeyRingLockedException.class,
                () -> new KeyRing(path().toString()));
        log.info("场景-缺失口令被拒 code=KEY_RING_LOCKED safe={}",
                !ex.getMessage().contains(material));
    }

    @Test
    void blankRootPasswordRejectedByProtector() {
        KeyRingLockedException ex = assertThrows(KeyRingLockedException.class,
                () -> new KeyMaterialProtector("   "));
        log.info("场景-空口令被拒 code=KEY_RING_LOCKED msg={}", ex.getMessage());
    }

    @Test
    void protectedFileTamperingIsRejected() throws Exception {
        KeyRing ring = new KeyRing(path().toString(), new KeyMaterialProtector(ROOT));
        new MasterKeyService(ring, ADMIN, false).ensureInitialized();
        ObjectMapper mapper = JsonMapper.builder().build();
        Path p = path();
        JsonNode node = mapper.readTree(p.toFile());
        byte[] ct = Base64.getDecoder().decode(node.path("ciphertext").asText());
        ct[0] ^= 0x01;
        ((com.fasterxml.jackson.databind.node.ObjectNode) node)
                .put("ciphertext", Base64.getEncoder().encodeToString(ct));
        mapper.writeValue(p.toFile(), node);

        assertThrows(KeyRingLockedException.class,
                () -> new KeyRing(p.toString(), new KeyMaterialProtector(ROOT)));
        log.info("场景-文件篡改被拒 code=KEY_RING_LOCKED");
    }
}
