package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

import com.github.h3yow.envelopeencryptionkeyringjava.errors.KeyRingLockedException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 密钥环落盘保护：用本地配置的根口令经 PBKDF2-HMAC-SHA256 派生出包裹密钥，
 * 再以 AES-256-GCM 对整个密钥环载荷做认证加密。
 *
 * <p>安全约定：
 * <ul>
 *   <li>每次包裹随机生成 salt 与 IV；口令错误时 GCM 认证失败，统一报
 *       {@link KeyRingLockedException}，不区分“文件损坏”与“口令错误”之外的细节。</li>
 *   <li>派生密钥与口令字节使用后立即清零；本类不提供任何读口令的方法。</li>
 *   <li>AAD 绑定格式标识，防止把密文载荷挪作其他格式。</li>
 * </ul>
 */
public class KeyMaterialProtector {

    /** 受保护密钥环文件的格式标识。 */
    public static final String FORMAT = "wrapped-v1";
    public static final String KDF = "PBKDF2WithHmacSHA256";

    static final int SALT_BYTES = 16;
    static final int GCM_IV_BYTES = 12;
    static final int GCM_TAG_BITS = 128;
    static final int KDF_ITERATIONS = 310_000;
    private static final int WRAP_KEY_BYTES = 32;
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final byte[] AAD = ("EK-KEYRING|" + FORMAT).getBytes(StandardCharsets.UTF_8);

    /** 包裹后的密文载荷及 KDF 参数。 */
    public record ProtectedBlob(int kdfIterations, byte[] salt, byte[] iv, byte[] ciphertext) {
    }

    private final char[] rootPassword;
    private final SecureRandom random = new SecureRandom();

    public KeyMaterialProtector(String rootPassword) {
        if (rootPassword == null || rootPassword.isBlank()) {
            throw new KeyRingLockedException("root password is required to protect the keyring");
        }
        this.rootPassword = rootPassword.toCharArray();
    }

    /** 加密任意明文字节（密钥环 JSON 载荷），返回可落盘的包裹结构。 */
    public ProtectedBlob wrap(byte[] plaintext) {
        if (plaintext == null) {
            throw new IllegalArgumentException("plaintext must not be null");
        }
        byte[] salt = new byte[SALT_BYTES];
        byte[] iv = new byte[GCM_IV_BYTES];
        random.nextBytes(salt);
        random.nextBytes(iv);
        byte[] wrapKey = deriveKey(salt, KDF_ITERATIONS);
        try {
            byte[] ct = gcm(Cipher.ENCRYPT_MODE, wrapKey, iv, plaintext);
            return new ProtectedBlob(KDF_ITERATIONS, salt, iv, ct);
        } finally {
            Arrays.fill(wrapKey, (byte) 0);
        }
    }

    /** 解密包裹载荷；口令错误或载荷被篡改时抛 {@link KeyRingLockedException}。 */
    public byte[] unwrap(ProtectedBlob blob) {
        if (blob == null || blob.salt() == null || blob.iv() == null || blob.ciphertext() == null
                || blob.kdfIterations() <= 0) {
            throw new KeyRingLockedException("protected keyring payload is malformed");
        }
        byte[] wrapKey = deriveKey(blob.salt(), blob.kdfIterations());
        try {
            return gcm(Cipher.DECRYPT_MODE, wrapKey, blob.iv(), blob.ciphertext());
        } finally {
            Arrays.fill(wrapKey, (byte) 0);
        }
    }

    private byte[] deriveKey(byte[] salt, int iterations) {
        KeySpec spec = new PBEKeySpec(rootPassword, salt, iterations, WRAP_KEY_BYTES * 8);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF);
            SecretKey tmp = factory.generateSecret(spec);
            byte[] raw = tmp.getEncoded();
            try {
                return Arrays.copyOf(raw, WRAP_KEY_BYTES);
            } finally {
                Arrays.fill(raw, (byte) 0);
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("key derivation unavailable", e);
        }
    }

    private byte[] gcm(int mode, byte[] key, byte[] iv, byte[] input) {
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            cipher.updateAAD(AAD);
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            // 解密失败（口令错误/篡改）与加密失败都不向外透出底层细节
            if (mode == Cipher.DECRYPT_MODE) {
                throw new KeyRingLockedException("failed to unlock the keyring; check the root password");
            }
            throw new IllegalStateException("keyring protection cipher failed", e);
        }
    }
}
