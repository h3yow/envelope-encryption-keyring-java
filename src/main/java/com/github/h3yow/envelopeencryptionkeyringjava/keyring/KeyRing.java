package com.github.h3yow.envelopeencryptionkeyringjava.keyring;

import com.github.h3yow.envelopeencryptionkeyringjava.config.EekrProperties;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CryptoException;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CryptoService;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.ErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * 内存密钥环 + 持久化协调。
 *
 * <p>并发模型：一把 {@link ReentrantReadWriteLock}。
 * <ul>
 *   <li>读锁：加解密、重包裹、按版本取密钥 —— 与彼此并发；</li>
 *   <li>写锁：生成、轮换、停用 —— 与一切互斥。</li>
 * </ul>
 * 状态变更遵循"先改内存、提交点处原子落盘、成功后才对外可见"的顺序，
 * 落盘失败则内存改动随回滚放弃，不会出现内存与磁盘长期分叉。
 *
 * <p>主密钥材料只以根密钥（口令经 PBKDF2 派生）包裹后的密文形式持久化。
 */
@Component
public class KeyRing {

    private static final Logger log = LoggerFactory.getLogger(KeyRing.class);

    private final KeyStore store;
    private final CryptoService cryptoService;
    private final EekrProperties props;
    private final SecureRandom random = new SecureRandom();
    private final ReadWriteLock lock = new ReentrantReadWriteLock();

    private KeyRingState state;
    /** 缓存：版本 -> 已解包的主密钥字节；落盘内容永不被本缓存替代。 */
    private java.util.Map<String, byte[]> materialCache = new java.util.HashMap<>();

    public KeyRing(KeyStore store, CryptoService cryptoService, EekrProperties props) {
        this.store = store;
        this.cryptoService = cryptoService;
        this.props = props;
        initialize();
    }

    // ================= 初始化 =================

    private void initialize() {
        lock.writeLock().lock();
        try {
            KeyRingState loaded = store.load();
            if (loaded == null || loaded.kdfSalt() == null || loaded.kdfSalt().length == 0) {
                byte[] salt = new byte[16];
                random.nextBytes(salt);
                state = new KeyRingState(salt, 0L, null, new ArrayList<>());
                createKeyLocked("bootstrap");
                log.info("keyring initialized with bootstrap master key version={}", state.currentVersion());
            } else {
                state = loaded;
                log.info("keyring loaded: versions={}, current={}", state.keys().size(), state.currentVersion());
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    // ================= 读操作（读锁） =================

    /** 取当前加密版本的主密钥材料；无可用密钥时拒绝。 */
    public KeyMaterial currentKey() {
        lock.readLock().lock();
        try {
            if (state.currentVersion() == null) {
                throw new CryptoException(ErrorCode.NO_ACTIVE_KEY, "no active master key");
            }
            return resolveLocked(state.currentVersion());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * 按版本取解密用主密钥材料。
     * 未知版本 -> KEY_VERSION_UNKNOWN；已停用 -> KEY_VERSION_DISABLED，两者可区分。
     */
    public KeyMaterial keyForDecryption(String version) {
        if (version == null || version.isBlank()) {
            throw new CryptoException(ErrorCode.CIPHERTEXT_MALFORMED, "missing key version");
        }
        lock.readLock().lock();
        try {
            MasterKeyRecord record = findRecordLocked(version);
            if (record == null) {
                log.info("decrypt key lookup denied: version={} reason=unknown", version);
                throw new CryptoException(ErrorCode.KEY_VERSION_UNKNOWN, "unknown key version: " + version);
            }
            if (record.status() == KeyStatus.DISABLED) {
                log.info("decrypt key lookup denied: version={} reason=disabled", version);
                throw new CryptoException(ErrorCode.KEY_VERSION_DISABLED, "key version disabled: " + version);
            }
            return resolveLocked(version);
        } finally {
            lock.readLock().unlock();
        }
    }

    /** 重包裹时按版本取密钥（已停用版本允许被重包裹迁移走），未知版本仍拒绝。 */
    public KeyMaterial keyForRewrapSource(String version) {
        lock.readLock().lock();
        try {
            MasterKeyRecord record = findRecordLocked(version);
            if (record == null) {
                throw new CryptoException(ErrorCode.KEY_VERSION_UNKNOWN, "unknown key version: " + version);
            }
            return resolveLocked(version);
        } finally {
            lock.readLock().unlock();
        }
    }

    /** 全部版本的脱敏视图（不含密钥材料）。 */
    public List<KeyViewSnapshot> listVersions() {
        lock.readLock().lock();
        try {
            List<KeyViewSnapshot> views = new ArrayList<>();
            for (MasterKeyRecord k : state.keys()) {
                views.add(new KeyViewSnapshot(k.version(), k.status().name(),
                        k.version().equals(state.currentVersion()), k.createdAt()));
            }
            return views;
        } finally {
            lock.readLock().unlock();
        }
    }

    // ================= 写操作（写锁） =================

    /** 生成并启用一把新主密钥（不改变 current）。 */
    public String createKey(String reason) {
        lock.writeLock().lock();
        try {
            return createKeyLocked(reason);
        } finally {
            lock.writeLock().unlock();
        }
    }

    private String createKeyLocked(String reason) {
        long counter = state.versionCounter() + 1;
        String version = "v" + counter;
        byte[] raw = cryptoService.generateKey();
        byte[] iv = cryptoService.generateIv();
        byte[] wrapped = cryptoService.encrypt(rootKeyLocked(), iv, wrapAad(version), raw);
        boolean first = state.keys().isEmpty();
        MasterKeyRecord record = new MasterKeyRecord(version, KeyStatus.ENABLED, wrapped, iv,
                System.currentTimeMillis(), first);
        List<MasterKeyRecord> keys = new ArrayList<>(state.keys());
        keys.add(0, record);
        String current = first ? version : state.currentVersion();
        persistLocked(new KeyRingState(state.kdfSalt(), counter, current, keys));
        materialCache.put(version, raw);
        log.info("master key created: version={} reason={} setCurrent={}", version, reason, first);
        return version;
    }

    /**
     * 有序轮换：生成新版本 -> 原子落盘 -> 切换 current 指针 -> 再次原子落盘。
     * 旧版本保持 ENABLED，历史数据仍可解密/重包裹。
     *
     * @return 新版本号
     */
    public String rotate(String reason) {
        lock.writeLock().lock();
        try {
            String previous = state.currentVersion();
            String newVersion = createKeyLocked("rotate:" + reason);
            List<MasterKeyRecord> keys = new ArrayList<>();
            for (MasterKeyRecord k : state.keys()) {
                keys.add(new MasterKeyRecord(k.version(), k.status(), k.wrappedKey(), k.wrapIv(),
                        k.createdAt(), k.version().equals(newVersion)));
            }
            persistLocked(new KeyRingState(state.kdfSalt(), state.versionCounter(), newVersion, keys));
            log.info("rotation complete: previous={} current={} reason={}", previous, newVersion, reason);
            return newVersion;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * 停用指定版本。当前版本不可停用（防止轮换后立刻无密钥可用）；
     * 未知版本拒绝；重复停用幂等返回 false。
     *
     * @return true 表示本次发生了状态变化
     */
    public boolean disable(String version) {
        lock.writeLock().lock();
        try {
            MasterKeyRecord record = findRecordLocked(version);
            if (record == null) {
                throw new CryptoException(ErrorCode.KEY_VERSION_UNKNOWN, "unknown key version: " + version);
            }
            if (version.equals(state.currentVersion())) {
                throw new CryptoException(ErrorCode.INVALID_REQUEST,
                        "cannot disable the current key version; rotate first");
            }
            if (record.status() == KeyStatus.DISABLED) {
                log.info("disable no-op: version={} already disabled", version);
                return false;
            }
            List<MasterKeyRecord> keys = new ArrayList<>();
            for (MasterKeyRecord k : state.keys()) {
                if (k.version().equals(version)) {
                    keys.add(new MasterKeyRecord(k.version(), KeyStatus.DISABLED, k.wrappedKey(),
                            k.wrapIv(), k.createdAt(), k.current()));
                } else {
                    keys.add(k);
                }
            }
            persistLocked(new KeyRingState(state.kdfSalt(), state.versionCounter(),
                    state.currentVersion(), keys));
            materialCache.remove(version);
            log.info("master key disabled: version={}", version);
            return true;
        } finally {
            lock.writeLock().unlock();
        }
    }

    // ================= 内部 =================

    private MasterKeyRecord findRecordLocked(String version) {
        for (MasterKeyRecord k : state.keys()) {
            if (k.version().equals(version)) {
                return k;
            }
        }
        return null;
    }

    private KeyMaterial resolveLocked(String version) {
        MasterKeyRecord record = findRecordLocked(version);
        if (record == null) {
            throw new CryptoException(ErrorCode.KEY_VERSION_UNKNOWN, "unknown key version: " + version);
        }
        byte[] raw = materialCache.get(version);
        if (raw == null) {
            raw = cryptoService.decryptOrThrow(rootKeyLocked(), record.wrapIv(),
                    wrapAad(version), record.wrappedKey());
            materialCache.put(version, raw);
        }
        return new KeyMaterial(version, raw);
    }

    private byte[] rootKeyLocked() {
        return cryptoService.deriveRootKey(props.rootKeyPassphrase(), state.kdfSalt(),
                props.kdfIterations());
    }

    private byte[] wrapAad(String version) {
        return ("MASTER:" + version).getBytes(StandardCharsets.UTF_8);
    }

    private void persistLocked(KeyRingState next) {
        store.save(next);
        state = next;
    }

    /** 已解析的主密钥材料。 */
    public record KeyMaterial(String version, byte[] raw) {
        @Override
        public String toString() {
            // 严禁在日志/异常中带出材料
            return "KeyMaterial(version=" + version + ")";
        }
    }

    /** 脱敏版本视图。 */
    public record KeyViewSnapshot(String version, String status, boolean current, long createdAt) {
    }
}
