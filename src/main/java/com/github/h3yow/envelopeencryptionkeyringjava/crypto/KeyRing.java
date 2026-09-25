package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
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

/**
 * 本地持久化密钥环：JSON 文件存储、原子落盘、读写锁保证并发下的一致视图。
 *
 * <p>轮换在写锁内单调递增版本号，保证有序；解密方持读锁，轮换/停用持写锁，
 * 因此加解密不会观察到半更新状态。
 */
public class KeyRing {

    private static final int KEY_BYTES = 32;

    /** 持久化结构。 */
    public static class State {
        public List<MasterKey> keys = List.of();
    }

    private final Path storagePath;
    private final ObjectMapper mapper = JsonMapper.builder().findAndAddModules().build();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
    private final Map<Integer, MasterKey> keys = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    public KeyRing(String storagePath) {
        this.storagePath = Path.of(storagePath);
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
            keys.clear();
            keys.putAll(sorted);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to load keyring from " + storagePath, e);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** 原子落盘：先写临时文件再原子改名，避免半写状态。 */
    private void persistLocked() {
        try {
            Path dir = storagePath.toAbsolutePath().getParent();
            Files.createDirectories(dir);
            State state = new State();
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
