package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

import com.github.h3yow.envelopeencryptionkeyringjava.errors.ContextMismatchException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.KeyDisabledException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.UnknownKeyVersionException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 重包裹迁移：解开历史密文的数据密钥（DEK），用当前活跃主密钥重新包裹。
 *
 * <p>数据密文、dataIv 与 contextTag 原样保留，因此迁移前后明文与 DEK 语义不变。
 * 已是当前版本的密文原样返回，重复提交天然幂等；整个判定与重包裹在密钥环读锁内完成，
 * 与轮换/停用/解密并发时不会观察到中间状态。
 */
public class RewrapService {

    private static final Logger log = LoggerFactory.getLogger(RewrapService.class);

    /** 迁移结果：migrated=false 表示幂等命中，未产生新密文。 */
    public record RewrapResult(String envelope, boolean migrated, int fromVersion, int toVersion) {
    }

    private final KeyRing keyRing;
    private final SecureRandom random = new SecureRandom();

    public RewrapService(KeyRing keyRing) {
        this.keyRing = keyRing;
    }

    /** 迁移单个密文到当前主密钥版本；已是当前版本时原样返回（幂等）。 */
    public String rewrap(String context, String encodedEnvelope) {
        return rewrapWithResult(context, encodedEnvelope).envelope();
    }

    public RewrapResult rewrapWithResult(String context, String encodedEnvelope) {
        if (context == null) {
            throw new IllegalArgumentException("context must not be null");
        }
        CiphertextEnvelope envelope = CiphertextEnvelope.parse(encodedEnvelope);
        keyRing.readLock().lock();
        try {
            MasterKey active = keyRing.activeKey()
                    .orElseThrow(() -> new IllegalStateException("no active master key available"));
            if (envelope.kekVersion() == active.getVersion()) {
                log.info("AUDIT action=rewrap kekVersion={} result=idempotent-noop",
                        envelope.kekVersion());
                return new RewrapResult(encodedEnvelope, false,
                        envelope.kekVersion(), active.getVersion());
            }
            MasterKey old = keyRing.find(envelope.kekVersion())
                    .orElseThrow(() -> {
                        log.warn("AUDIT action=rewrap kekVersion={} result=rejected reason=unknown-version",
                                envelope.kekVersion());
                        return new UnknownKeyVersionException(
                                "unknown key version: " + envelope.kekVersion());
                    });
            if (old.getStatus() == KeyStatus.DISABLED) {
                log.warn("AUDIT action=rewrap kekVersion={} result=rejected reason=key-disabled",
                        envelope.kekVersion());
                throw new KeyDisabledException("key version " + envelope.kekVersion() + " is disabled");
            }
            byte[] oldMaterial = EnvelopeCipher.decodeMaterial(old);
            byte[] newMaterial = EnvelopeCipher.decodeMaterial(active);
            byte[] dek = null;
            try {
                dek = EnvelopeCipher.gcm(false, oldMaterial, envelope.wrapIv(),
                        envelope.wrappedDek(), EnvelopeCipher.wrapAad(envelope.kekVersion()));
                if (!MessageDigest.isEqual(EnvelopeCipher.contextTag(dek, context),
                        envelope.contextTag())) {
                    log.warn("AUDIT action=rewrap kekVersion={} result=rejected reason=context-mismatch",
                            envelope.kekVersion());
                    throw new ContextMismatchException("encryption context does not match");
                }
                byte[] wrapIv = new byte[EnvelopeCipher.GCM_IV_BYTES];
                random.nextBytes(wrapIv);
                byte[] wrappedDek = EnvelopeCipher.gcm(true, newMaterial, wrapIv, dek,
                        EnvelopeCipher.wrapAad(active.getVersion()));
                CiphertextEnvelope migrated = new CiphertextEnvelope(
                        CiphertextEnvelope.CURRENT_FORMAT_VERSION, active.getVersion(),
                        wrapIv, wrappedDek, envelope.dataIv(), envelope.ciphertext(),
                        envelope.contextTag());
                log.info("AUDIT action=rewrap fromVersion={} toVersion={} result=success",
                        envelope.kekVersion(), active.getVersion());
                return new RewrapResult(migrated.encode(), true,
                        envelope.kekVersion(), active.getVersion());
            } finally {
                if (dek != null) {
                    Arrays.fill(dek, (byte) 0);
                }
                Arrays.fill(oldMaterial, (byte) 0);
                Arrays.fill(newMaterial, (byte) 0);
            }
        } finally {
            keyRing.readLock().unlock();
        }
    }
}
