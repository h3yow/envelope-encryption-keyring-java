package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

import com.github.h3yow.envelopeencryptionkeyringjava.errors.MalformedCiphertextException;
import java.util.Base64;

/**
 * 信封密文的结构化表示，携带可解析的密钥版本线索。
 *
 * <p>编码格式（单行，点分七段）：
 * {@code EK1.<kekVersion>.<b64(wrapIv)>.<b64(wrappedDek)>.<b64(dataIv)>.<b64(ciphertext)>.<b64(contextTag)>}
 *
 * <p>contextTag 为数据密钥对约定上下文的 HMAC 截断值，用于在解密时
 * 将“上下文不匹配”与“密文篡改”区分为不同错误。
 */
public record CiphertextEnvelope(
        int formatVersion,
        int kekVersion,
        byte[] wrapIv,
        byte[] wrappedDek,
        byte[] dataIv,
        byte[] ciphertext,
        byte[] contextTag) {

    public static final String PREFIX = "EK1";
    public static final int CURRENT_FORMAT_VERSION = 1;
    private static final int SEGMENTS = 7;

    /** 序列化为单行字符串。 */
    public String encode() {
        Base64.Encoder b64 = Base64.getEncoder();
        return String.join(".",
                PREFIX,
                Integer.toString(kekVersion),
                b64.encodeToString(wrapIv),
                b64.encodeToString(wrappedDek),
                b64.encodeToString(dataIv),
                b64.encodeToString(ciphertext),
                b64.encodeToString(contextTag));
    }

    /** 解析密文；版本信息不完整或结构损坏时抛出 {@link MalformedCiphertextException}。 */
    public static CiphertextEnvelope parse(String encoded) {
        if (encoded == null || encoded.isBlank()) {
            throw new MalformedCiphertextException("ciphertext is empty");
        }
        String[] parts = encoded.split("\\.", -1);
        if (parts.length != SEGMENTS) {
            throw new MalformedCiphertextException(
                    "ciphertext must have " + SEGMENTS + " segments but has " + parts.length);
        }
        if (!PREFIX.equals(parts[0])) {
            throw new MalformedCiphertextException("unsupported format prefix: " + parts[0]);
        }
        final int kekVersion;
        try {
            kekVersion = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            throw new MalformedCiphertextException("key version clue is not a number");
        }
        if (kekVersion <= 0) {
            throw new MalformedCiphertextException("key version clue must be positive");
        }
        Base64.Decoder b64 = Base64.getDecoder();
        byte[][] fields = new byte[5][];
        for (int i = 0; i < 5; i++) {
            try {
                fields[i] = b64.decode(parts[i + 2]);
            } catch (IllegalArgumentException e) {
                throw new MalformedCiphertextException("segment " + (i + 2) + " is not valid base64");
            }
            if (fields[i].length == 0) {
                throw new MalformedCiphertextException("segment " + (i + 2) + " is empty");
            }
        }
        return new CiphertextEnvelope(CURRENT_FORMAT_VERSION, kekVersion,
                fields[0], fields[1], fields[2], fields[3], fields[4]);
    }
}
