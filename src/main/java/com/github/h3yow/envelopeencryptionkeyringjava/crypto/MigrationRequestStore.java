package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 迁移请求的按编号幂等记录存储（进程内 + 本地 JSON 落盘）。
 *
 * <p>淘汰规则是确定性的：按访问序维护（插入或重放命中都会刷新），超过
 * {@code maxRecords} 时从迭代顺序头部移除“最久未被重放”的记录；
 * 两条记录访问时刻相同时由插入序号决定先后，先插入者先被淘汰。
 *
 * <p>记录中保存输入指纹（SHA-256）用于冲突判定，保存首次产出的密文用于重放；
 * 本类的日志只出现请求编号与指纹前缀，绝不打印密文全文。
 */
public class MigrationRequestStore {

    private static final Logger log = LoggerFactory.getLogger(MigrationRequestStore.class);

    /** 单条幂等记录。 */
    public static class Entry {
        public String requestId;
        public String fingerprint;
        public String envelope;
        public boolean migrated;
        public int fromVersion;
        public int toVersion;
        public long createdAt;
        public long lastSeenAt;
        public long seq;
    }

    /** 持久化结构。 */
    public static class State {
        public long nextSeq = 0;
        public Map<String, Entry> entries = new LinkedHashMap<>();
    }

    private final Path storagePath;
    private final int maxRecords;
    private final ObjectMapper mapper = JsonMapper.builder().findAndAddModules().build();
    // accessOrder=true：get/put 都会刷新访问序
    private final LinkedHashMap<String, Entry> entries = new LinkedHashMap<>(16, 0.75f, true);
    private long nextSeq = 0;

    public MigrationRequestStore(String storagePath, int maxRecords) {
        if (storagePath == null || storagePath.isBlank()) {
            throw new IllegalArgumentException("migration store path must not be empty");
        }
        if (maxRecords < 1) {
            throw new IllegalArgumentException("migrationMaxRecords must be >= 1");
        }
        this.storagePath = Path.of(storagePath);
        this.maxRecords = maxRecords;
        load();
    }

    /** 查找记录；命中即刷新访问序（最近重放的记录最后被淘汰）。未命中返回 null。 */
    public synchronized Entry find(String requestId) {
        Entry e = entries.get(requestId);
        if (e != null) {
            e.lastSeenAt = System.currentTimeMillis();
            persist();
        }
        return e;
    }

    /**
     * 插入一条新记录并按上限淘汰。
     *
     * @return 因本次插入而被淘汰的请求编号（按淘汰顺序，可能为空）
     */
    public synchronized List<String> insert(Entry entry) {
        entry.seq = nextSeq++;
        if (entry.createdAt == 0) {
            entry.createdAt = System.currentTimeMillis();
        }
        entry.lastSeenAt = entry.createdAt;
        entries.put(entry.requestId, entry);
        List<String> evicted = evictIfNeeded();
        persist();
        return evicted;
    }

    public synchronized int size() {
        return entries.size();
    }

    public int maxRecords() {
        return maxRecords;
    }

    private List<String> evictIfNeeded() {
        List<String> evicted = new ArrayList<>();
        while (entries.size() > maxRecords) {
            Map.Entry<String, Entry> oldest = entries.entrySet().iterator().next();
            String id = oldest.getKey();
            entries.remove(id);
            evicted.add(id);
            log.info("AUDIT action=migration-evict requestId={} fingerprint={} reason=capacity reasonDetail=lru",
                    id, prefix(oldest.getValue().fingerprint));
        }
        return evicted;
    }

    private void load() {
        try {
            if (!Files.exists(storagePath)) {
                return;
            }
            State state = mapper.readValue(storagePath.toFile(), State.class);
            // 落盘顺序即为上次访问序（LinkedHashMap 序列化保持迭代顺序）
            entries.clear();
            entries.putAll(state.entries);
            nextSeq = state.nextSeq;
            if (entries.size() > maxRecords) {
                List<String> evicted = evictIfNeeded();
                persist();
                log.info("AUDIT action=migration-evict-on-load evicted={} reason=capacity", evicted.size());
            }
        } catch (IOException e) {
            throw new UncheckedIOException("failed to load migration requests from " + storagePath, e);
        }
    }

    /** 原子落盘：先写临时文件再原子改名。 */
    private void persist() {
        try {
            Path dir = storagePath.toAbsolutePath().getParent();
            Files.createDirectories(dir);
            State state = new State();
            state.nextSeq = nextSeq;
            state.entries = new LinkedHashMap<>(entries);
            Path tmp = Files.createTempFile(dir, "migration-", ".tmp");
            try {
                mapper.writeValue(tmp.toFile(), state);
                Files.move(tmp, storagePath,
                        StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } finally {
                Files.deleteIfExists(tmp);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("failed to persist migration requests to " + storagePath, e);
        }
    }

    static String prefix(String fingerprint) {
        if (fingerprint == null) {
            return "-";
        }
        return fingerprint.substring(0, Math.min(8, fingerprint.length()));
    }

    /** 仅供日志安全使用：对字节做短摘要的 Base64 前缀。 */
    public static String shortToken(byte[] data) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(data);
            return Base64.getEncoder().encodeToString(digest).substring(0, 8);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
