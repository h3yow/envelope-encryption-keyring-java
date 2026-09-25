package com.github.h3yow.envelopeencryptionkeyringjava.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CryptoException;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.ErrorCode;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.RewrapResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 基于本地文件的重包裹幂等记录存储。
 *
 * <p>每个 requestId 一个 JSON 文件（原子写入），进程内用 synchronized 保证
 * 同 requestId 的并发请求只有一个执行真实迁移，其余拿到同一份结果（重放）。
 * requestId 相同但输入摘要不同 -> {@link ErrorCode#IDEMPOTENCY_CONFLICT}。
 */
@Component
public class IdempotencyStore {

    private static final Logger log = LoggerFactory.getLogger(IdempotencyStore.class);

    private final Path directory;
    private final ObjectMapper objectMapper;
    private final int maxRecords;
    private final Map<String, IdempotencyRecord> cache = new LinkedHashMap<>();

    public IdempotencyStore(Path rewrapDir, ObjectMapper objectMapper,
                            com.github.h3yow.envelopeencryptionkeyringjava.config.EekrProperties props) {
        this.directory = rewrapDir;
        this.objectMapper = objectMapper;
        this.maxRecords = Math.max(100, props.idempotency().maxRecords());
    }

    /**
     * 查找已提交过的记录。
     *
     * @return 已有记录；从未见过该 requestId 返回 null
     * @throws CryptoException 同 requestId 但输入摘要不一致
     */
    public synchronized IdempotencyRecord find(String requestId, String inputDigest) {
        IdempotencyRecord cached = cache.get(requestId);
        if (cached == null) {
            cached = loadFromDisk(requestId);
            if (cached != null) {
                cache.put(requestId, cached);
            }
        }
        if (cached == null) {
            return null;
        }
        if (!cached.inputDigest().equals(inputDigest)) {
            log.info("idempotency conflict: requestId={} basis=different-input-under-same-id", requestId);
            throw new CryptoException(ErrorCode.IDEMPOTENCY_CONFLICT,
                    "requestId already used with a different payload");
        }
        return cached;
    }

    /** 原子提交一条新记录；并发下若已有同 requestId 记录则返回已有记录。 */
    public synchronized IdempotencyRecord commitIfAbsent(IdempotencyRecord record) {
        IdempotencyRecord existing = find(record.requestId(), record.inputDigest());
        if (existing != null) {
            return existing;
        }
        writeToDisk(record);
        cache.put(record.requestId(), record);
        evictIfNeeded();
        log.info("idempotency record committed: requestId={} outputVersion={}",
                record.requestId(), record.outputVersion());
        return record;
    }

    public static RewrapResponse toResponse(IdempotencyRecord record, boolean replayed) {
        return new RewrapResponse(record.outputCiphertext(), record.outputVersion(), replayed);
    }

    private IdempotencyRecord loadFromDisk(String requestId) {
        Path file = fileOf(requestId);
        if (!Files.exists(file)) {
            return null;
        }
        try {
            return objectMapper.readValue(Files.readAllBytes(file), IdempotencyRecord.class);
        } catch (IOException e) {
            throw new CryptoException(ErrorCode.INTERNAL_ERROR, "idempotency record unreadable", e);
        }
    }

    private void writeToDisk(IdempotencyRecord record) {
        try {
            Files.createDirectories(directory);
            Path target = fileOf(record.requestId());
            Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
            byte[] raw = objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsBytes(record);
            Files.write(tmp, raw);
            try {
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicUnsupported) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
            try {
                Files.setPosixFilePermissions(target,
                        java.util.Set.of(java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
            } catch (UnsupportedOperationException | IOException ignored) {
                // 非 POSIX 文件系统忽略权限收紧
            }
        } catch (IOException e) {
            throw new CryptoException(ErrorCode.INTERNAL_ERROR, "idempotency record persistence failed", e);
        }
    }

    private Path fileOf(String requestId) {
        // 防御路径穿越：requestId 只允许安全字符
        if (!requestId.matches("[A-Za-z0-9._-]{1,128}")) {
            throw new CryptoException(ErrorCode.INVALID_REQUEST,
                    "requestId must be 1-128 chars of [A-Za-z0-9._-]");
        }
        return directory.resolve("rewrap-" + requestId + ".json");
    }

    private void evictIfNeeded() {
        // LinkedHashMap 默认插入序；超限时淘汰最老的内存条目（磁盘文件保留）
        while (cache.size() > maxRecords) {
            Map.Entry<String, IdempotencyRecord> eldest = cache.entrySet().iterator().next();
            cache.remove(eldest.getKey());
        }
    }
}
