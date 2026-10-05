package com.github.h3yow.envelopeencryptionkeyringjava.migration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 迁移请求记录存储：JSON 文件持久化、有上限、确定性淘汰最旧记录。
 *
 * <p>内存中以插入序 {@link LinkedHashMap} 保存，超过上限时按插入顺序淘汰最旧记录
 * （确定性规则：FIFO）；每次写入后原子落盘（临时文件 + atomic rename），
 * 服务重启后最近提交过的请求仍能正常重放。记录只含请求编号、输入指纹与结果密文，
 * 不含任何密钥材料或明文。
 */
public class MigrationRecordStore {

    private static final Logger log = LoggerFactory.getLogger(MigrationRecordStore.class);

    /** 持久化结构。 */
    public static class State {
        public List<MigrationRecord> records = List.of();
    }

    private final Path storagePath;
    private final int maxRecords;
    private final ObjectMapper mapper = JsonMapper.builder().findAndAddModules().build();
    private final LinkedHashMap<String, MigrationRecord> records = new LinkedHashMap<>();

    public MigrationRecordStore(String storagePath, int maxRecords) {
        if (maxRecords <= 0) {
            throw new IllegalArgumentException("maxRecords must be positive");
        }
        this.storagePath = Path.of(storagePath);
        this.maxRecords = maxRecords;
        load();
    }

    /** 按请求编号查找记录。 */
    public synchronized Optional<MigrationRecord> find(String requestId) {
        return Optional.ofNullable(records.get(requestId));
    }

    /** 写入一条记录并落盘；超过上限时按插入顺序淘汰最旧记录（FIFO）。 */
    public synchronized void put(MigrationRecord record) {
        records.put(record.getRequestId(), record);
        while (records.size() > maxRecords) {
            String eldest = records.keySet().iterator().next();
            records.remove(eldest);
            log.info("AUDIT action=migration-record-evict requestId={} reason=max-records-exceeded"
                    + " maxRecords={}", eldest, maxRecords);
        }
        persistLocked();
    }

    /** 当前记录数。 */
    public synchronized int size() {
        return records.size();
    }

    private void load() {
        if (!Files.exists(storagePath)) {
            return;
        }
        try {
            State state = mapper.readValue(storagePath.toFile(), State.class);
            records.clear();
            for (MigrationRecord record : state.records) {
                records.put(record.getRequestId(), record);
                while (records.size() > maxRecords) {
                    records.remove(records.keySet().iterator().next());
                }
            }
            log.info("AUDIT action=migration-records-load records={} result=success", records.size());
        } catch (IOException e) {
            throw new UncheckedIOException("failed to load migration records from " + storagePath, e);
        }
    }

    private void persistLocked() {
        try {
            Path dir = storagePath.toAbsolutePath().getParent();
            Files.createDirectories(dir);
            State state = new State();
            state.records = new ArrayList<>(records.values());
            Path tmp = Files.createTempFile(dir, "migration-records-", ".tmp");
            mapper.writeValue(tmp.toFile(), state);
            Files.move(tmp, storagePath,
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to persist migration records to " + storagePath, e);
        }
    }

    /** 仅供测试/诊断：当前全部请求编号（按插入序）。 */
    synchronized Map<String, MigrationRecord> snapshot() {
        return Map.copyOf(records);
    }
}
