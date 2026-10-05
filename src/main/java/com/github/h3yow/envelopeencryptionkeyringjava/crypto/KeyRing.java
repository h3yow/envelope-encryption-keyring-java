package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.KeyRingLockedException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 本地持久化密钥环：JSON 文件存储、原子落盘、读写锁保证并发下的一致视图。
 *
 * <p>落盘格式有两种，加载时自动识别：
 * <ul>
 *   <li>受保护格式（{@link KeyMaterialProtector#FORMAT}）：整个密钥环载荷用根口令派生密钥
 *       做 AES-GCM 认证加密，文件中不含任何明文密钥材料。</li>
 *   <li>旧明文格式：直接为密钥环 JSON。配置了根口令时可正常加载，并在加载时一次性
 *       原子升级为受保护格式；未配置根口令时仅允许在显式的无保护构造方式下读取
 *       （兼容历史用法）。</li>
 * </ul>
 *
 * <p>轮换在写锁内单调递增版本号，保证有序；解密方持读锁，轮换/停用持写锁，
 * 因此加解密不会观察到半更新状态。
 */
public class KeyRing {

    private static final Logger log = LoggerFactory.getLogger(KeyRing.class);
    private static final int KEY_BYTES = 32;

    /** 旧明文持久化结构。 */
    public static class State {
        public List<MasterKey> keys = List.of();
    }

    /** 受保护落盘结构；字段中只有密文与 KDF 参数，没有任何密钥材料。 */
    public static class ProtectedState {
        public String format = KeyMaterialProtector.FORMAT;
        public String kdf = KeyMaterialProtector.KDF;
        public int kdfIterations;
        public String salt;
        public String iv;
        public String ciphertext;
    }

    private final Path storagePath;
    private final ObjectMapper mapper = JsonMapper.builder().findAndAddModules().build();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
    private final Map<Integer, MasterKey> keys = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final KeyMaterialProtector protector;

    /** 无落盘保护构造（仅限无保护场景/历史用法；生产装配必须提供根口令）。 */
    public KeyRing(String storagePath) {
        this(storagePath, null);
    }

    public KeyRing(String storagePath, KeyMaterialProtector protector) {
        this.storagePath = Path.of(storagePath);
        this.protector = protector;
        loadAndMaybeUpgrade();
    }

    /** 读锁：解密/查找期间阻止轮换与停用提交。 */
    public Lock readLock() {
        return lock.readLock();
    }

    /** 写锁：轮换/停用/重包裹协调使用。 */
    public Lock writeLock() {
        return lock.writeLock();
    }

    public Optional<MasterKey> find(int version) {
        lock.readLock().lock();
        try {
            return Optional.ofNullable(keys.get(version));
        } finally {
            lock.readLock().unlock();
        }
    }

    public Optional<MasterKey> activeKey() {
        lock.readLock().lock();
        try {
            return keys.values().stream()
                    .filter(k -> k.getStatus() == KeyStatus.ACTIVE)
                    .max((a, b) -> Integer.compare(a.getVersion(), b.getVersion()));
        } finally {
            lock.readLock().unlock();
        }
    }

    /** 有序轮换：写锁内生成版本号严格递增的新主密钥并原子落盘。 */
    public MasterKey rotate() {
        lock.writeLock().lock();
        try {
            int newVersion = highestVersionLocked() + 1;
            byte[] material = new byte[KEY_BYTES];
            random.nextBytes(material);
            MasterKey key = new MasterKey();
            key.setVersion(newVersion);
            key.setStatus(KeyStatus.ACTIVE);
            key.setMaterialBase64(Base64.getEncoder().encodeToString(material));
            key.setCreatedAt(Instant.now());
            keys.put(newVersion, key);
            persistLocked();
            return key;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** 停用指定版本；不存在时抛 {@link IllegalArgumentException}。 */
    public void disable(int version) {
        lock.writeLock().lock();
        try {
            MasterKey key = keys.get(version);
            if (key == null) {
                throw new IllegalArgumentException("key version not found: " + version);
            }
            key.setStatus(KeyStatus.DISABLED);
            persistLocked();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public int highestVersion() {
        lock.readLock().lock();
        try {
            return highestVersionLocked();
        } finally {
            lock.readLock().unlock();
        }
    }

    public int size() {
        lock.readLock().lock();
        try {
            return keys.size();
        } finally {
            lock.readLock().unlock();
        }
    }

    private int highestVersionLocked() {
        return keys.keySet().stream().mapToInt(Integer::intValue).max().orElse(0);
    }

    private void loadAndMaybeUpgrade() {
        lock.writeLock().lock();
        try {
            if (!Files.exists(storagePath)) {
                return;
            }
            byte[] raw = Files.readAllBytes(storagePath);
            JsonNode root = mapper.readTree(raw);
            boolean upgradedFromLegacy = false;
            byte[] stateJson;
            String format = root.path("format").asText("");
            if (KeyMaterialProtector.FORMAT.equals(format)) {
                if (protector == null) {
                    // 绝不退化为明文：受保护文件缺少根口令时直接拒绝
                    throw new KeyRingLockedException(
                            "keyring file is password-protected but no root password was configured");
                }
                ProtectedState ps = mapper.treeToValue(root, ProtectedState.class);
                KeyMaterialProtector.ProtectedBlob blob = new KeyMaterialProtector.ProtectedBlob(
                        ps.kdfIterations,
                        Base64.getDecoder().decode(ps.salt),
                        Base64.getDecoder().decode(ps.iv),
                        Base64.getDecoder().decode(ps.ciphertext));
                stateJson = protector.unwrap(blob);
            } else {
                // 旧明文格式：原样加载
                stateJson = raw;
                upgradedFromLegacy = true;
            }
            replaceKeys(mapper.readValue(stateJson, State.class));
            if (upgradedFromLegacy && protector != null) {
                // 平滑升级：立即以受保护格式原子重写，旧密文的解密能力不受影响
                persistLocked();
                log.info("AUDIT action=keyring-upgrade from=plaintext to=wrapped-v1 result=success");
            }
        } catch (IOException e) {
            throw new UncheckedIOException("failed to load keyring from " + storagePath, e);
        } finally {
            lock.writeLock().unlock();
        }
    }

    private void replaceKeys(State state) {
        // TreeMap 排序仅为确定性校验，实际存储用 ConcurrentHashMap
        Map<Integer, MasterKey> sorted = new TreeMap<>();
        for (MasterKey key : state.keys) {
            sorted.put(key.getVersion(), key);
        }
        keys.clear();
        keys.putAll(sorted);
    }

    /** 原子落盘：先写临时文件再原子改名，避免半写状态；配置根口令时写受保护格式。 */
    private void persistLocked() {
        try {
            Path dir = storagePath.toAbsolutePath().getParent();
            Files.createDirectories(dir);
            State state = new State();
            state.keys = List.copyOf(new TreeMap<>(keys).values());
            byte[] payload = mapper.writeValueAsBytes(state);
            Path tmp = Files.createTempFile(dir, "keyring-", ".tmp");
            try {
                if (protector == null) {
                    Files.write(tmp, payload);
                } else {
                    KeyMaterialProtector.ProtectedBlob blob = protector.wrap(payload);
                    ProtectedState ps = new ProtectedState();
                    ps.kdfIterations = blob.kdfIterations();
                    ps.salt = Base64.getEncoder().encodeToString(blob.salt());
                    ps.iv = Base64.getEncoder().encodeToString(blob.iv());
                    ps.ciphertext = Base64.getEncoder().encodeToString(blob.ciphertext());
                    mapper.writeValue(tmp.toFile(), ps);
                }
                Files.move(tmp, storagePath,
                        StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } finally {
                // 异常路径下尽力清理临时文件；改名成功后临时文件已不存在
                Files.deleteIfExists(tmp);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("failed to persist keyring to " + storagePath, e);
        }
    }
}
