package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

import com.github.h3yow.envelopeencryptionkeyringjava.errors.KeyRingUnlockException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 密钥环落盘保护：用本地配置的根口令经 PBKDF2 派生根密钥（KEK），
 * 以 AES-256-GCM 把每个主密钥材料单独包裹后再落盘；光看密钥环文件读不出任何密钥材料。
 *
 * <p>根口令未配置时直接拒绝构建（不退化为明文）；根口令错误或落盘数据损坏时
 * 抛出 {@link KeyRingUnlockException}，异常消息不含口令或密钥材料。
 */
public class KeyRingProtection {

    /** KDF 参数，随密钥环文件持久化（盐与迭代次数不是秘密）。 */
    public static class KdfParams {
        public String algo = ALGO;
        public String saltBase64 = "";
        public int iterations = ITERATIONS;
    }

    static final String ALGO = "PBKDF2WithHmacSHA256";
    static final int ITERATIONS = 210_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final byte[] WRAP_AAD = "EK1|keyring|wrap".getBytes(StandardCharsets.UTF_8);

    private final char[] rootKey;
    private final SecureRandom random = new SecureRandom();

    private KeyRingProtection(String rootKey) {
        this.rootKey = rootKey.toCharArray();
    }

    /** 从根口令构建；根口令为空时拒绝（不退化为明文落盘）。 */
    public static KeyRingProtection fromRootKey(String rootKey) {
        if (rootKey == null || rootKey.isBlank()) {
            throw new KeyRingUnlockException(
                    "keyring root key is not configured; refusing to handle master key material");
        }
        return new KeyRingProtection(rootKey);
    }

    /** 生成一组新的 KDF 参数（随机盐、固定算法与迭代次数）。 */
    public KdfParams newKdfParams() {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        KdfParams params = new KdfParams();
        params.saltBase64 = Base64.getEncoder().encodeToString(salt);
        return params;
    }

    /** 用指定 KDF 参数包裹主密钥材料，返回 [iv, 包裹结果]。 */
    public byte[][] wrap(byte[] material, KdfParams params) {
        byte[] iv = new byte[GCM_IV_BYTES];
        random.nextBytes(iv);
        byte[] wrapped = gcm(true, derive(params), iv, material);
        return new byte[][] {iv, wrapped};
    }

    /** 用指定 KDF 参数解开主密钥材料；根口令错误或数据损坏时抛 {@link KeyRingUnlockException}。 */
    public byte[] unwrap(byte[] iv, byte[] wrapped, KdfParams params) {
        try {
            return gcm(false, derive(params), iv, wrapped);
        } catch (KeyRingUnlockException e) {
            throw e;
        }
    }

    private byte[] gcm(boolean encrypt, byte[] kek, byte[] iv, byte[] input) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                    new SecretKeySpec(kek, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            cipher.updateAAD(WRAP_AAD);
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            // 不透露是口令错误还是数据损坏，更不包含任何材料
            throw new KeyRingUnlockException(
                    "failed to unwrap keyring master key material (wrong root key or corrupted file)");
        } finally {
            Arrays.fill(kek, (byte) 0);
        }
    }

    private byte[] derive(KdfParams params) {
        if (!ALGO.equals(params.algo)) {
            throw new KeyRingUnlockException("unsupported keyring kdf algo: " + params.algo);
        }
        if (params.iterations <= 0 || params.saltBase64 == null || params.saltBase64.isBlank()) {
            throw new KeyRingUnlockException("keyring kdf parameters are missing or invalid");
        }
        try {
            byte[] salt = Base64.getDecoder().decode(params.saltBase64);
            PBEKeySpec spec = new PBEKeySpec(rootKey, salt, params.iterations, KEY_BITS);
            try {
                return SecretKeyFactory.getInstance(ALGO).generateSecret(spec).getEncoded();
            } finally {
                spec.clearPassword();
            }
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new KeyRingUnlockException("failed to derive keyring root key");
        }
    }
}
