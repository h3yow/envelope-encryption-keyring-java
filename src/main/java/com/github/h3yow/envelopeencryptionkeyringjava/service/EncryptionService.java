package com.github.h3yow.envelopeencryptionkeyringjava.service;

import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CryptoException;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.DigestUtil;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.CryptoService;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.EnvelopeFormat;
import com.github.h3yow.envelopeencryptionkeyringjava.crypto.ErrorCode;
import com.github.h3yow.envelopeencryptionkeyringjava.keyring.KeyRing;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.DecryptRequest;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.DecryptResponse;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.EncryptRequest;
import com.github.h3yow.envelopeencryptionkeyringjava.service.dto.EncryptResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * 信封加解密入口。
 *
 * <p>加密：每次生成独立的一次性数据密钥（DEK），DEK 经当前主密钥（KEK）包裹；
 * 约定上下文以 SHA-256 摘要形式参与两段 GCM 的 AAD。
 *
 * <p>解密判定顺序保证错误原因可区分：
 * <ol>
 *   <li>结构解析失败 -> CIPHERTEXT_MALFORMED</li>
 *   <li>密钥版本未知/停用 -> KEY_VERSION_UNKNOWN / KEY_VERSION_DISABLED</li>
 *   <li>上下文摘要不一致 -> CONTEXT_MISMATCH（在触碰密码学原语前判定）</li>
 *   <li>GCM 标签验证失败 -> CIPHERTEXT_TAMPERED（包裹 DEK 或数据密文被篡改）</li>
 * </ol>
 */
@Service
public class EncryptionService {

    private static final Logger log = LoggerFactory.getLogger(EncryptionService.class);

    private final KeyRing keyRing;
    private final CryptoService cryptoService;

    public EncryptionService(KeyRing keyRing, CryptoService cryptoService) {
        this.keyRing = keyRing;
        this.cryptoService = cryptoService;
    }

    public EncryptResponse encrypt(EncryptRequest request) {
        validateText(request.plaintext(), "plaintext");
        String context = request.context() == null ? "" : request.context();

        KeyRing.KeyMaterial kek = keyRing.currentKey();
        byte[] dek = cryptoService.generateKey();
        byte[] wkIv = cryptoService.generateIv();
        byte[] dIv = cryptoService.generateIv();
        byte[] ctxHash = EnvelopeFormat.contextHash(context);

        byte[] plaintextBytes = request.plaintext().getBytes(StandardCharsets.UTF_8);
        byte[] wrappedKey = cryptoService.encrypt(kek.raw(), wkIv,
                EnvelopeFormat.wrappedKeyAad(kek.version(), ctxHash), dek);
        byte[] ciphertext = cryptoService.encrypt(dek, dIv,
                EnvelopeFormat.dataAad(ctxHash), plaintextBytes);

        EnvelopeFormat.Envelope envelope = new EnvelopeFormat.Envelope(
                kek.version(), ctxHash, wkIv, wrappedKey, dIv, ciphertext);
        String encoded = Base64.getEncoder().encodeToString(EnvelopeFormat.serialize(envelope));

        log.info("encrypt decision: keyVersion={} plaintextSha256={} contextSha256={} basis=current-key",
                kek.version(), digestPrefix(plaintextBytes), digestPrefix(ctxHash));
        return new EncryptResponse(encoded, kek.version());
    }

    public DecryptResponse decrypt(DecryptRequest request) {
        validateText(request.ciphertext(), "ciphertext");
        String context = request.context() == null ? "" : request.context();

        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(request.ciphertext());
        } catch (IllegalArgumentException e) {
            throw new CryptoException(ErrorCode.CIPHERTEXT_MALFORMED, "ciphertext is not valid base64", e);
        }

        // 1) 结构
        EnvelopeFormat.Envelope envelope = EnvelopeFormat.parse(raw);

        // 2) 版本（未知/停用在此被区分拒绝）
        KeyRing.KeyMaterial kek = keyRing.keyForDecryption(envelope.keyVersion());

        // 3) 上下文（摘要比对，先于密码学调用）
        byte[] expectedCtxHash = EnvelopeFormat.contextHash(context);
        if (!MessageDigest.isEqual(expectedCtxHash, envelope.contextHash())) {
            log.info("decrypt denied: keyVersion={} basis=context-hash-mismatch expected={} actual={}",
                    envelope.keyVersion(), digestPrefix(expectedCtxHash), digestPrefix(envelope.contextHash()));
            throw new CryptoException(ErrorCode.CONTEXT_MISMATCH, "encryption context does not match");
        }

        // 4) 先解包 DEK；失败即密文（含版本/IV/包裹体）被篡改
        byte[] dek;
        try {
            dek = cryptoService.decryptOrThrow(kek.raw(), envelope.wrappedKeyIv(),
                    EnvelopeFormat.wrappedKeyAad(kek.version(), expectedCtxHash), envelope.wrappedKey());
        } catch (CryptoException e) {
            log.info("decrypt denied: keyVersion={} basis=wrapped-key-tag-invalid reason=tampered",
                    envelope.keyVersion());
            throw new CryptoException(ErrorCode.CIPHERTEXT_TAMPERED, "wrapped data key authentication failed", e);
        }

        // 5) 解数据；失败即数据密文被篡改
        byte[] plaintextBytes;
        try {
            plaintextBytes = cryptoService.decryptOrThrow(dek, envelope.dataIv(),
                    EnvelopeFormat.dataAad(expectedCtxHash), envelope.ciphertext());
        } catch (CryptoException e) {
            log.info("decrypt denied: keyVersion={} basis=data-tag-invalid reason=tampered",
                    envelope.keyVersion());
            throw new CryptoException(ErrorCode.CIPHERTEXT_TAMPERED, "data ciphertext authentication failed", e);
        }

        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
        log.info("decrypt decision: keyVersion={} plaintextSha256={} basis=tag-validated",
                envelope.keyVersion(), digestPrefix(plaintextBytes));
        return new DecryptResponse(plaintext);
    }

    private void validateText(String value, String name) {
        if (value == null || value.isEmpty()) {
            throw new CryptoException(ErrorCode.INVALID_REQUEST, name + " must not be empty");
        }
    }

    private String digestPrefix(byte[] bytes) {
        return DigestUtil.sha256Prefix(bytes);
    }
}
