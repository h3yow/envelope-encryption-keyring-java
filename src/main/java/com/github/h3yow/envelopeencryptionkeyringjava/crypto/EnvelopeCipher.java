package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

import com.github.h3yow.envelopeencryptionkeyringjava.errors.CiphertextIntegrityException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.ContextMismatchException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.KeyDisabledException;
import com.github.h3yow.envelopeencryptionkeyringjava.errors.UnknownKeyVersionException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 信封加解密入口：每次加密生成独立数据密钥（DEK），用当前活跃主密钥（KEK）包裹；
 * 约定上下文同时作为 GCM 附加认证数据并生成 contextTag，用于区分上下文不匹配与篡改。
 *
 * <p>底层 {@link GeneralSecurityException} 一律映射为可区分的对外异常，不原样透出。
 */
public class EnvelopeCipher {

    private static final Logger log = LoggerFactory.getLogger(EnvelopeCipher.class);

    static final int DEK_BYTES = 32;
    static final int GCM_IV_BYTES = 12;
    static final int GCM_TAG_BITS = 128;
    static final int CONTEXT_TAG_BYTES = 16;
    private static final String AES_GCM = "AES/GCM/NoPadding";

    private final KeyRing keyRing;
    private final SecureRandom random = new SecureRandom();

    public EnvelopeCipher(KeyRing keyRing) {
        this.keyRing = keyRing;
    }

    /** 使用当前活跃主密钥加密；返回携带版本线索的信封串。 */
    public String encrypt(String context, byte[] plaintext) {
        if (context == null || plaintext == null) {
            throw new IllegalArgumentException("context and plaintext must not be null");
        }
        keyRing.readLock().lock();
        try {
            MasterKey kek = keyRing.activeKey()
                    .orElseThrow(() -> new IllegalStateException("no active master key available"));
            byte[] kekMaterial = decodeMaterial(kek);
            byte[] dek = new byte[DEK_BYTES];
            random.nextBytes(dek);
            try {
                byte[] dataIv = randomBytes(GCM_IV_BYTES);
                byte[] ciphertext = gcm(true, dek, dataIv, plaintext, contextAad(context));
                byte[] wrapIv = randomBytes(GCM_IV_BYTES);
                byte[] wrappedDek = gcm(true, kekMaterial, wrapIv, dek, wrapAad(kek.getVersion()));
                byte[] contextTag = contextTag(dek, context);
                CiphertextEnvelope envelope = new CiphertextEnvelope(
                        CiphertextEnvelope.CURRENT_FORMAT_VERSION, kek.getVersion(),
                        wrapIv, wrappedDek, dataIv, ciphertext, contextTag);
                log.info("AUDIT action=encrypt kekVersion={} plaintextBytes={} result=success",
                        kek.getVersion(), plaintext.length);
                return envelope.encode();
            } finally {
                Arrays.fill(dek, (byte) 0);
                Arrays.fill(kekMaterial, (byte) 0);
            }
        } finally {
            keyRing.readLock().unlock();
        }
    }

    /** 解密信封串；对未知版本、停用版本、篡改、上下文不匹配分别抛出可区分异常。 */
    public byte[] decrypt(String context, String encodedEnvelope) {
        if (context == null) {
            throw new IllegalArgumentException("context must not be null");
        }
        CiphertextEnvelope envelope = CiphertextEnvelope.parse(encodedEnvelope);
        keyRing.readLock().lock();
        try {
            MasterKey kek = keyRing.find(envelope.kekVersion())
                    .orElseThrow(() -> {
                        log.warn("AUDIT action=decrypt kekVersion={} result=rejected reason=unknown-version",
                                envelope.kekVersion());
                        return new UnknownKeyVersionException(
                                "unknown key version: " + envelope.kekVersion());
                    });
            if (kek.getStatus() == KeyStatus.DISABLED) {
                log.warn("AUDIT action=decrypt kekVersion={} result=rejected reason=key-disabled",
                        envelope.kekVersion());
                throw new KeyDisabledException("key version " + envelope.kekVersion() + " is disabled");
            }
            byte[] kekMaterial = decodeMaterial(kek);
            byte[] dek = null;
            try {
                dek = gcm(false, kekMaterial, envelope.wrapIv(), envelope.wrappedDek(),
                        wrapAad(envelope.kekVersion()));
            } catch (CiphertextIntegrityException e) {
                log.warn("AUDIT action=decrypt kekVersion={} result=rejected reason=wrap-integrity",
                        envelope.kekVersion());
                throw e;
            }
            try {
                if (!MessageDigest.isEqual(contextTag(dek, context), envelope.contextTag())) {
                    log.warn("AUDIT action=decrypt kekVersion={} result=rejected reason=context-mismatch",
                            envelope.kekVersion());
                    throw new ContextMismatchException("encryption context does not match");
                }
                byte[] plaintext = gcm(false, dek, envelope.dataIv(), envelope.ciphertext(),
                        contextAad(context));
                log.info("AUDIT action=decrypt kekVersion={} plaintextBytes={} result=success",
                        envelope.kekVersion(), plaintext.length);
                return plaintext;
            } finally {
                Arrays.fill(dek, (byte) 0);
                Arrays.fill(kekMaterial, (byte) 0);
            }
        } finally {
            keyRing.readLock().unlock();
        }
    }

    static byte[] wrapAad(int kekVersion) {
        return ("EK1|wrap|v" + kekVersion).getBytes(StandardCharsets.UTF_8);
    }

    static byte[] contextAad(String context) {
        return ("EK1|data|" + context).getBytes(StandardCharsets.UTF_8);
    }

    static byte[] contextTag(byte[] dek, String context) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(dek, "HmacSHA256"));
            byte[] full = mac.doFinal(("EK1|ctx|" + context).getBytes(StandardCharsets.UTF_8));
            return Arrays.copyOf(full, CONTEXT_TAG_BYTES);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    static byte[] decodeMaterial(MasterKey key) {
        return Base64.getDecoder().decode(key.getMaterialBase64());
    }

    private byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        random.nextBytes(b);
        return b;
    }

    /** GCM 加解密；认证失败统一映射为 {@link CiphertextIntegrityException}。 */
    static byte[] gcm(boolean encrypt, byte[] key, byte[] iv, byte[] input, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            cipher.updateAAD(aad);
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            // 不向调用方透出底层密码学异常细节
            throw new CiphertextIntegrityException("authenticated decryption failed");
        }
    }
}
