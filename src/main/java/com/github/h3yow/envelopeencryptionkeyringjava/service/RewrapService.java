package com.github.h3yow.envelopeencryptionkeyringjava.service;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CryptoException;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CryptoService;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.DigestUtil;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.EnvelopeFormat;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.ErrorCode;
import com.github.h3yow.envelopeencryptionkeyringjava.keyring.KeyRing;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.RewrapRequest;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.RewrapResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * 既有密文重包裹迁移。
 *
 * <p>不变量：DEK 字节与数据密文段保持不变，因此迁移前后明文语义完全一致；
 * 只更换"包裹 DEK 的主密钥版本、包裹 IV、包裹密文"以及密文头中的版本线索。
 *
 * <p>一致性：
 * <ul>
 *   <li>源版本已经是当前版本 -> 幂等 no-op，原样返回（replayed=false）；</li>
 *   <li>同一 requestId 重复提交且输入一致 -> 返回首次结果，replayed=true；</li>
 *   <li>重包裹全程使用读锁取密钥快照，不会读到轮换中间态；</li>
 *   <li>结果提交是原子的：要么返回旧密文/新密文，不会产生半迁移输出。</li>
 * </ul>
 */
@Service
public class RewrapService {

    private static final Logger log = LoggerFactory.getLogger(RewrapService.class);

    private final KeyRing keyRing;
    private final CryptoService cryptoService;
    private final IdempotencyStore idempotencyStore;

    public RewrapService(KeyRing keyRing, CryptoService cryptoService,
                         IdempotencyStore idempotencyStore) {
        this.keyRing = keyRing;
        this.cryptoService = cryptoService;
        this.idempotencyStore = idempotencyStore;
    }

    public RewrapResponse rewrap(RewrapRequest request) {
        if (request == null || request.ciphertext() == null || request.ciphertext().isEmpty()) {
            throw new CryptoException(ErrorCode.INVALID_REQUEST, "ciphertext must not be empty");
        }
        if (request.requestId() == null || request.requestId().isBlank()) {
            throw new CryptoException(ErrorCode.INVALID_REQUEST, "requestId is required for rewrap");
        }
        String context = request.context() == null ? "" : request.context();
        String inputDigest = DigestUtil.sha256Prefix(request.ciphertext() + "|" + context);

        // 幂等短路：重复提交直接返回首次结果
        IdempotencyRecord prior = idempotencyStore.find(request.requestId(), inputDigest);
        if (prior != null) {
            log.info("rewrap replay: requestId={} keyVersion={} basis=idempotent-hit inputDigest={}",
                    request.requestId(), prior.outputVersion(), inputDigest);
            return IdempotencyStore.toResponse(prior, true);
        }

        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(request.ciphertext());
        } catch (IllegalArgumentException e) {
            throw new CryptoException(ErrorCode.CIPHERTEXT_MALFORMED, "ciphertext is not valid base64", e);
        }
        EnvelopeFormat.Envelope envelope = EnvelopeFormat.parse(raw);

        // 目标版本在执行期间取一次快照，避免与轮换交叉产生歧义
        KeyRing.KeyMaterial targetKek = keyRing.currentKey();

        if (envelope.keyVersion().equals(targetKek.version())) {
            // 已是最新版本：no-op，天然幂等，不写幂等记录
            log.info("rewrap no-op: requestId={} keyVersion={} basis=already-current inputDigest={}",
                    request.requestId(), targetKek.version(), inputDigest);
            return new RewrapResponse(request.ciphertext(), targetKek.version(), false);
        }

        // 源版本允许已停用（迁移停用密钥下的数据是合法维护操作），但未知版本拒绝
        KeyRing.KeyMaterial sourceKek = keyRing.keyForRewrapSource(envelope.keyVersion());

        byte[] expectedCtxHash = EnvelopeFormat.contextHash(context);
        if (!MessageDigest.isEqual(expectedCtxHash, envelope.contextHash())) {
            log.info("rewrap denied: requestId={} keyVersion={} basis=context-hash-mismatch",
                    request.requestId(), envelope.keyVersion());
            throw new CryptoException(ErrorCode.CONTEXT_MISMATCH, "encryption context does not match");
        }

        // 解包 DEK：源密文必须完整可信，篡改在此暴露
        byte[] dek;
        try {
            dek = cryptoService.decryptOrThrow(sourceKek.raw(), envelope.wrappedKeyIv(),
                    EnvelopeFormat.wrappedKeyAad(sourceKek.version(), expectedCtxHash),
                    envelope.wrappedKey());
        } catch (CryptoException e) {
            log.info("rewrap denied: requestId={} keyVersion={} basis=wrapped-key-tag-invalid",
                    request.requestId(), envelope.keyVersion());
            throw new CryptoException(ErrorCode.CIPHERTEXT_TAMPERED,
                    "wrapped data key authentication failed", e);
        }

        // 用目标 KEK 重新包裹同一个 DEK；数据密文与 dataIv 原样保留
        byte[] newWkIv = cryptoService.generateIv();
        byte[] newWrapped = cryptoService.encrypt(targetKek.raw(), newWkIv,
                EnvelopeFormat.wrappedKeyAad(targetKek.version(), expectedCtxHash), dek);

        EnvelopeFormat.Envelope migrated = new EnvelopeFormat.Envelope(
                targetKek.version(), expectedCtxHash, newWkIv, newWrapped,
                envelope.dataIv(), envelope.ciphertext());
        String output = Base64.getEncoder().encodeToString(EnvelopeFormat.serialize(migrated));

        IdempotencyRecord record = new IdempotencyRecord(
                request.requestId(), inputDigest, output, targetKek.version(),
                System.currentTimeMillis());
        IdempotencyRecord committed = idempotencyStore.commitIfAbsent(record);
        boolean replayed = committed != record;

        log.info("rewrap complete: requestId={} fromVersion={} toVersion={} basis=dek-preserved inputDigest={} replayed={}",
                request.requestId(), envelope.keyVersion(), targetKek.version(), inputDigest, replayed);
        return IdempotencyStore.toResponse(committed, replayed);
    }
}
