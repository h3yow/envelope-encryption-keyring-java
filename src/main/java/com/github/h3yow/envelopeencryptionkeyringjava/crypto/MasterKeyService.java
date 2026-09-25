package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

import com.github.h3yow.envelopeencryptionkeyringjava.errors.UnauthorizedOperationException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 主密钥管理服务：生成、启停与有序轮换。
 *
 * <p>所有管理操作要求管理令牌；令牌比对使用常量时间算法，
 * 鉴权失败只返回通用错误，不泄露任何密钥材料或令牌信息。
 */
public class MasterKeyService {

    private static final Logger log = LoggerFactory.getLogger(MasterKeyService.class);

    private final KeyRing keyRing;
    private final String adminToken;
    private final boolean allowDisableLastActive;

    public MasterKeyService(KeyRing keyRing, String adminToken, boolean allowDisableLastActive) {
        this.keyRing = keyRing;
        this.adminToken = adminToken == null ? "" : adminToken;
        this.allowDisableLastActive = allowDisableLastActive;
    }

    /** 有序轮换：生成版本号严格递增的新主密钥。 */
    public MasterKey rotate(String callerToken) {
        requireAdmin(callerToken, "rotate");
        MasterKey key = keyRing.rotate();
        log.info("AUDIT action=rotate newVersion={} result=success", key.getVersion());
        return key;
    }

    /** 停用指定版本；默认拒绝停用最后一个活跃密钥。 */
    public void disable(String callerToken, int version) {
        requireAdmin(callerToken, "disable");
        keyRing.writeLock().lock();
        try {
            MasterKey key = keyRing.find(version)
                    .orElseThrow(() -> new IllegalArgumentException("key version not found: " + version));
            if (!allowDisableLastActive && key.getStatus() == KeyStatus.ACTIVE
                    && keyRing.activeKey().map(MasterKey::getVersion).orElse(-1) == version) {
                log.warn("AUDIT action=disable version={} result=rejected reason=last-active-key", version);
                throw new IllegalStateException("refusing to disable the last active key version " + version);
            }
            keyRing.disable(version);
            log.info("AUDIT action=disable version={} result=success", version);
        } finally {
            keyRing.writeLock().unlock();
        }
    }

    /** 确保密钥环已初始化（首次使用时生成首个主密钥），幂等且并发安全。 */
    public MasterKey ensureInitialized() {
        var existing = keyRing.activeKey();
        if (existing.isPresent()) {
            return existing.get();
        }
        keyRing.writeLock().lock();
        try {
            return keyRing.activeKey().orElseGet(() -> {
                MasterKey key = keyRing.rotate();
                log.info("AUDIT action=bootstrap-generate version={} result=success", key.getVersion());
                return key;
            });
        } finally {
            keyRing.writeLock().unlock();
        }
    }

    private void requireAdmin(String callerToken, String action) {
        String presented = callerToken == null ? "" : callerToken;
        boolean ok = !adminToken.isEmpty() && MessageDigest.isEqual(
                presented.getBytes(StandardCharsets.UTF_8),
                adminToken.getBytes(StandardCharsets.UTF_8));
        if (!ok) {
            // 不透露令牌是否存在、长度或任何密钥材料
            log.warn("AUDIT action={} result=rejected reason=unauthorized", action);
            throw new UnauthorizedOperationException("admin credentials required for " + action);
        }
    }
}
