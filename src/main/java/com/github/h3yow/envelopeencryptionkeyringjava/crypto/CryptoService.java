package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * AES-256-GCM 原语封装。
 *
 * <p>所有方法对外只抛 {@link CryptoException}（{@link ErrorCode#INTERNAL_ERROR}），
 * 底层 GeneralSecurityException 作为 cause 保留但不向接口层透出。
 * 解密时 GCM 校验失败同样包装为 INTERNAL_ERROR，由上层结合校验顺序翻译为
 * CONTEXT_MISMATCH / CIPHERTEXT_TAMPERED。
 */
public class CryptoService {

    /** AES 密钥长度（字节）。 */
    public static final int KEY_LEN = 32;
    /** GCM 标准推荐 IV 长度（字节）。 */
    public static final int IV_LEN = 12;
    /** GCM 认证标签长度（位）。 */
    public static final int TAG_BITS = 128;

    private static final String KEY_ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";

    private final SecureRandom secureRandom = new SecureRandom();

    /** 生成 256 位随机密钥。 */
    public byte[] generateKey() {
        byte[] key = new byte[KEY_LEN];
        secureRandom.nextBytes(key);
        return key;
    }

    /** 生成 96 位随机 IV。 */
    public byte[] generateIv() {
        byte[] iv = new byte[IV_LEN];
        secureRandom.nextBytes(iv);
        return iv;
    }

    /**
     * 通过 PBKDF2-HMAC-SHA256 从口令派生 256 位根密钥。
     *
     * @param passphrase 口令
     * @param salt       盐（随密钥环文件持久化）
     * @param iterations PBKDF2 迭代次数
     */
    public byte[] deriveRootKey(String passphrase, byte[] salt, int iterations) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
            PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, iterations, KEY_LEN * 8);
            byte[] derived = factory.generateSecret(spec).getEncoded();
            spec.clearPassword();
            return derived;
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.INTERNAL_ERROR, "root key derivation failed", e);
        }
    }

    /** AES-GCM 加密。aad 可为 null。 */
    public byte[] encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, toKey(key), new GCMParameterSpec(TAG_BITS, iv));
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.INTERNAL_ERROR, "encryption primitive failed", e);
        }
    }

    /**
     * AES-GCM 解密并验证认证标签。
     *
     * @throws CryptoException 标签校验失败时错误码为 INTERNAL_ERROR，由上层按校验顺序翻译
     */
    public byte[] decryptOrThrow(byte[] key, byte[] iv, byte[] aad, byte[] ciphertextWithTag) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, toKey(key), new GCMParameterSpec(TAG_BITS, iv));
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ciphertextWithTag);
        } catch (GeneralSecurityException e) {
            // 不区分 BadPadding/AEADBadTag，避免向上透出底层细节
            throw new CryptoException(ErrorCode.INTERNAL_ERROR, "authentication failed", e);
        }
    }

    private SecretKey toKey(byte[] raw) {
        return new SecretKeySpec(raw, KEY_ALGORITHM);
    }
}
