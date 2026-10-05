package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.KeyRingUnlockException;
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
 * <p>落盘格式 v2：主密钥材料由根口令派生的根密钥包裹（AES-256-GCM），
 * 文件中只出现 wrappedMaterialBase64/wrapIvBase64 与 KDF 参数，读不出明文材料。
 * 旧格式 v1（明文 materialBase64）文件仍可加载，加载后立即以 v2 重新落盘完成平滑升级；
 * 升级不改变任何密钥材料，因此既有密文的解密、轮换与迁移结论不变。
 *
 * <p>轮换在写锁内单调递增版本号，保证有序；解密方持读锁，轮换/停用持写锁，
 * 因此加解密不会观察到半更新状态。
 */
public class KeyRing {

    private static final Logger log = LoggerFactory.getLogger(KeyRing.class);

    private static final int KEY_BYTES = 32;
    static final int FORMAT_V1_PLAINTEXT = 1;
    static final int FORMAT_V2_WRAPPED = 2;

    /** 持久化结构。 */
    public static class State {
        /** 缺省视为旧格式 v1（明文材料）。 */
        public int formatVersion = FORMAT_V1_PLAINTEXT;
        public KeyRingProtection.KdfParams kdf;
        public List<MasterKey> keys = List.of();
    }

    private final Path storagePath;
    private final KeyRingProtection protection;
    private final ObjectMapper mapper = JsonMapper.builder().findAndAddModules().build();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
    private final Map<Integer, MasterKey> keys = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    public KeyRing(String storagePath, KeyRingProtection protection) {
        if (protection == null) {
            // 根口令未配置：拒绝启动，绝不退化为明文落盘
            throw new KeyRingUnlockException(
                    "keyring root key is not configured; refusing to open keyring at " + storagePath);
        }
        this.storagePath = Path.of(storagePath);
        this.protection = protection;
        load();
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

    private void load() {
        lock.writeLock().lock();
        try {
            if (!Files.exists(storagePath)) {
                return;
            }
            State state = mapper.readValue(storagePath.toFile(), State.class);
            // TreeMap 排序仅为确定性校验，实际存储用 ConcurrentHashMap
            Map<Integer, MasterKey> sorted = new TreeMap<>();
            for (MasterKey key : state.keys) {
                sorted.put(key.getVersion(), key);
            }
            if (state.formatVersion >= FORMAT_V2_WRAPPED) {
                // 新格式：用根口令解开每个主密钥材料；口令错误时拒绝启动
                if (state.kdf == null) {
                    throw new KeyRingUnlockException("keyring file is missing kdf parameters");
                }
                Base64.Decoder b64 = Base64.getDecoder();
                for (MasterKey key : sorted.values()) {
                    byte[] material = protection.unwrap(
                            b64.decode(key.getWrapIvBase64()),
                            b64.decode(key.getWrappedMaterialBase64()),
                            state.kdf);
                    key.setMaterialBase64(Base64.getEncoder().encodeToString(material));
                }
                keys.clear();
                keys.putAll(sorted);
                log.info("AUDIT action=keyring-load format=v2 keys={} result=success", keys.size());
            } else {
                // 旧格式：明文材料可读入内存，但必须立即升级为 v2 落盘
                for (MasterKey key : sorted.values()) {
                    if (key.getMaterialBase64() == null || key.getMaterialBase64().isBlank()) {
                        throw new KeyRingUnlockException(
                                "legacy keyring file is missing key material for version "
                                        + key.getVersion());
                    }
                }
                keys.clear();
                keys.putAll(sorted);
                persistLocked();
                log.info("AUDIT action=keyring-upgrade from=v1 to=v2 keys={} result=success",
                        keys.size());
            }
        } catch (IOException e) {
            throw new UncheckedIOException("failed to load keyring from " + storagePath, e);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** 原子落盘：材料用根密钥包裹后先写临时文件再原子改名，避免半写状态与明文落盘。 */
    private void persistLocked() {
        try {
            Path dir = storagePath.toAbsolutePath().getParent();
            Files.createDirectories(dir);
            State state = new State();
            state.formatVersion = FORMAT_V2_WRAPPED;
            state.kdf = protection.newKdfParams();
            Base64.Encoder b64 = Base64.getEncoder();
            Base64.Decoder b64dec = Base64.getDecoder();
            for (MasterKey key : new TreeMap<>(keys).values()) {
                byte[] material = b64dec.decode(key.getMaterialBase64());
                byte[][] wrapped = protection.wrap(material, state.kdf);
                key.setWrapIvBase64(b64.encodeToString(wrapped[0]));
                key.setWrappedMaterialBase64(b64.encodeToString(wrapped[1]));
            }
            state.keys = List.copyOf(new TreeMap<>(keys).values());
            Path tmp = Files.createTempFile(dir, "keyring-", ".tmp");
            mapper.writeValue(tmp.toFile(), state);
            Files.move(tmp, storagePath,
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to persist keyring to " + storagePath, e);
        }
    }
}
