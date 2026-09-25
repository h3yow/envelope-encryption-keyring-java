package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 信封密文的二进制序列化格式。
 *
 * <pre>
 * magic      4 字节  "EEKR"
 * format     1 字节  格式版本（当前 = 1）
 * kvLen      2 字节  密钥版本字符串长度
 * keyVersion kvLen   UTF-8 密钥版本线索
 * ctxHash    32 字节 约定上下文的 SHA-256 摘要（用于在 GCM 验证前区分上下文不匹配）
 * wkIv       12 字节 包裹数据密钥所用 IV
 * wkLen      2 字节  包裹后数据密钥长度
 * wrappedKey wkLen   密文（含 16 字节 GCM tag）
 * dIv        12 字节 加密数据所用 IV
 * ctLen      4 字节  数据密文长度
 * ciphertext ctLen   密文（含 16 字节 GCM tag）
 * </pre>
 *
 * 包装数据密钥的 AAD = "WK" || keyVersion bytes || ctxHash；
 * 加密数据的 AAD = "DT" || ctxHash。
 */
public final class EnvelopeFormat {

    public static final byte[] MAGIC = {'E', 'E', 'K', 'R'};
    public static final byte FORMAT_VERSION = 1;
    public static final int SHA256_LEN = 32;

    private EnvelopeFormat() {
    }

    /** 解析后的信封结构。 */
    public record Envelope(
            String keyVersion,
            byte[] contextHash,
            byte[] wrappedKeyIv,
            byte[] wrappedKey,
            byte[] dataIv,
            byte[] ciphertext) {
    }

    /** 上下文摘要：SHA-256（null 按空串处理）。 */
    public static byte[] contextHash(String context) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            if (context != null) {
                digest.update(context.getBytes(StandardCharsets.UTF_8));
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(ErrorCode.INTERNAL_ERROR, "sha-256 unavailable", e);
        }
    }

    /** 包装数据密钥的 AAD。 */
    public static byte[] wrappedKeyAad(String keyVersion, byte[] contextHash) {
        return concat(prefixedTag("WK"), keyVersion.getBytes(StandardCharsets.UTF_8), contextHash);
    }

    /** 加密业务数据的 AAD。 */
    public static byte[] dataAad(byte[] contextHash) {
        return concat(prefixedTag("DT"), contextHash);
    }

    private static byte[] prefixedTag(String tag) {
        return tag.getBytes(StandardCharsets.UTF_8);
    }

    /** 序列化为字节数组。 */
    public static byte[] serialize(Envelope envelope) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (DataOutputStream dos = new DataOutputStream(out)) {
            dos.write(MAGIC);
            dos.writeByte(FORMAT_VERSION);
            byte[] kv = envelope.keyVersion().getBytes(StandardCharsets.UTF_8);
            if (kv.length > 65535) {
                throw new CryptoException(ErrorCode.INTERNAL_ERROR, "key version too long");
            }
            dos.writeShort(kv.length);
            dos.write(kv);
            writeFixed(dos, envelope.contextHash(), SHA256_LEN, "context hash");
            writeFixed(dos, envelope.wrappedKeyIv(), CryptoService.IV_LEN, "wrapped key iv");
            dos.writeShort(envelope.wrappedKey().length);
            dos.write(envelope.wrappedKey());
            writeFixed(dos, envelope.dataIv(), CryptoService.IV_LEN, "data iv");
            dos.writeInt(envelope.ciphertext().length);
            dos.write(envelope.ciphertext());
        } catch (IOException e) {
            throw new CryptoException(ErrorCode.INTERNAL_ERROR, "envelope serialization failed", e);
        }
        return out.toByteArray();
    }

    /**
     * 解析字节数组。任何长度/边界/魔数/格式版本问题都翻译为
     * {@link ErrorCode#CIPHERTEXT_MALFORMED}，不透出底层 IO 异常。
     */
    public static Envelope parse(byte[] raw) {
        if (raw == null || raw.length < MAGIC.length + 1) {
            throw new CryptoException(ErrorCode.CIPHERTEXT_MALFORMED, "ciphertext too short");
        }
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(raw))) {
            byte[] magic = new byte[MAGIC.length];
            in.readFully(magic);
            for (int i = 0; i < MAGIC.length; i++) {
                if (magic[i] != MAGIC[i]) {
                    throw new CryptoException(ErrorCode.CIPHERTEXT_MALFORMED, "bad magic");
                }
            }
            int format = in.readUnsignedByte();
            if (format != FORMAT_VERSION) {
                throw new CryptoException(ErrorCode.CIPHERTEXT_MALFORMED, "unsupported format version: " + format);
            }
            int kvLen = in.readUnsignedShort();
            if (kvLen == 0) {
                throw new CryptoException(ErrorCode.CIPHERTEXT_MALFORMED, "missing key version");
            }
            String keyVersion = readString(in, kvLen);
            byte[] contextHash = readFixed(in, SHA256_LEN, "context hash");
            byte[] wkIv = readFixed(in, CryptoService.IV_LEN, "wrapped key iv");
            int wkLen = in.readUnsignedShort();
            if (wkLen == 0) {
                throw new CryptoException(ErrorCode.CIPHERTEXT_MALFORMED, "missing wrapped data key");
            }
            byte[] wrappedKey = readFixed(in, wkLen, "wrapped key");
            byte[] dataIv = readFixed(in, CryptoService.IV_LEN, "data iv");
            int ctLen = in.readInt();
            if (ctLen <= 0) {
                throw new CryptoException(ErrorCode.CIPHERTEXT_MALFORMED, "missing data ciphertext");
            }
            byte[] ciphertext = readFixed(in, ctLen, "ciphertext");
            if (in.read() != -1) {
                throw new CryptoException(ErrorCode.CIPHERTEXT_MALFORMED, "trailing bytes");
            }
            return new Envelope(keyVersion, contextHash, wkIv, wrappedKey, dataIv, ciphertext);
        } catch (IOException e) {
            throw new CryptoException(ErrorCode.CIPHERTEXT_MALFORMED, "ciphertext truncated or corrupted");
        }
    }

    private static void writeFixed(DataOutputStream dos, byte[] value, int expected, String name)
            throws IOException {
        if (value == null || value.length != expected) {
            throw new CryptoException(ErrorCode.INTERNAL_ERROR, "bad " + name + " length");
        }
        dos.write(value);
    }

    private static byte[] readFixed(DataInputStream in, int len, String name) throws IOException {
        if (len < 0 || len > 1024 * 1024) {
            throw new CryptoException(ErrorCode.CIPHERTEXT_MALFORMED, "bad length for " + name);
        }
        byte[] buf = new byte[len];
        in.readFully(buf);
        return buf;
    }

    private static String readString(DataInputStream in, int len) throws IOException {
        byte[] buf = new byte[len];
        in.readFully(buf);
        return new String(buf, StandardCharsets.UTF_8);
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }
}
