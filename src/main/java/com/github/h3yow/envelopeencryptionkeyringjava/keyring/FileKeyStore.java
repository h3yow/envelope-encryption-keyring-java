package com.github.h3yow.envelopeencryptionkeyringjava.keyring;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CryptoException;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.ErrorCode;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * 基于本地 JSON 文件的密钥环持久化。
 *
 * <p>文件权限尽量收紧到属主可读写；写入走临时文件 + 原子 move，避免崩溃产生半截文件。
 * 并发安全由 {@link KeyRing} 的全局锁保证，本类自身不做加锁。
 */
@Component
public class FileKeyStore implements KeyStore {

    static final String FILE_NAME = "keyring.json";

    private final Path file;
    private final ObjectMapper objectMapper;

    public FileKeyStore(@Qualifier("keyRingFile") Path keyRingFile, ObjectMapper objectMapper) {
        this.file = keyRingFile;
        this.objectMapper = objectMapper;
    }

    @Override
    public KeyRingState load() {
        if (!Files.exists(file)) {
            return null;
        }
        try {
            byte[] raw = Files.readAllBytes(file);
            return objectMapper.readValue(raw, KeyRingState.class);
        } catch (IOException e) {
            throw new CryptoException(ErrorCode.INTERNAL_ERROR, "keyring state unreadable; refusing to reset", e);
        }
    }

    @Override
    public void save(KeyRingState state) {
        try {
            Files.createDirectories(file.getParent());
            Path tmp = file.resolveSibling(FILE_NAME + ".tmp");
            byte[] raw = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(state);
            Files.write(tmp, raw);
            try {
                Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicUnsupported) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
            try {
                Files.setPosixFilePermissions(file,
                        java.util.Set.of(java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
            } catch (UnsupportedOperationException | IOException ignored) {
                // 非 POSIX 文件系统（如 Windows）忽略权限收紧
            }
        } catch (IOException e) {
            throw new CryptoException(ErrorCode.INTERNAL_ERROR, "keyring state persistence failed", e);
        }
    }

    @Override
    public String toString() {
        // 防止日志意外带出路径以外信息；路径不含密钥材料
        return "FileKeyStore(" + file + ")";
    }
}
