package com.github.h3yow.envelopeencryptionkeyringjava.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** SHA-256 摘要工具，用于审计日志，绝不输出原文。 */
public final class DigestUtil {

    private DigestUtil() {
    }

    public static String sha256Prefix(byte[] bytes) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(bytes);
            return HexFormat.of().formatHex(d, 0, 8);
        } catch (NoSuchAlgorithmException e) {
            return "n/a";
        }
    }

    public static String sha256Prefix(String text) {
        return sha256Prefix(text == null ? new byte[0] : text.getBytes(StandardCharsets.UTF_8));
    }
}
